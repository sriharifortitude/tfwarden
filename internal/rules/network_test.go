package rules

import (
	"testing"

	"github.com/sriharifortitude/tfwarden/internal/planjson"
)

func ingress(rules ...map[string]any) map[string]any {
	list := make([]any, len(rules))
	for i, r := range rules {
		list[i] = r
	}
	return map[string]any{"ingress": list}
}

func TestSecurityGroupOpenSensitivePort(t *testing.T) {
	ssh := res("aws_security_group.ssh", "aws_security_group",
		ingress(map[string]any{"cidr_blocks": []any{"0.0.0.0/0"}, "from_port": float64(22), "to_port": float64(22), "protocol": "tcp"}))
	safe := res("aws_security_group.safe", "aws_security_group",
		ingress(map[string]any{"cidr_blocks": []any{"10.0.0.0/8"}, "from_port": float64(443), "to_port": float64(443), "protocol": "tcp"}))
	restrictedButOpenPort := res("aws_security_group.https", "aws_security_group",
		ingress(map[string]any{"cidr_blocks": []any{"0.0.0.0/0"}, "from_port": float64(443), "to_port": float64(443), "protocol": "tcp"}))
	rangeCoveringSsh := res("aws_security_group.range", "aws_security_group",
		ingress(map[string]any{"cidr_blocks": []any{"0.0.0.0/0"}, "from_port": float64(20), "to_port": float64(25), "protocol": "tcp"}))

	resources := []planjson.Resource{ssh, safe, restrictedButOpenPort, rangeCoveringSsh}
	rule := ruleByID("security-group-open-sensitive-port")

	got := findingsFor(rule, "aws_security_group.ssh", resources)
	if len(got) != 1 || got[0].Message != "ingress from 0.0.0.0/0 allows SSH (port 22)" {
		t.Fatalf("ssh: %+v", got)
	}
	if got := findingsFor(rule, "aws_security_group.safe", resources); len(got) != 0 {
		t.Fatalf("private cidr: %+v", got)
	}
	if got := findingsFor(rule, "aws_security_group.https", resources); len(got) != 0 {
		t.Fatalf("open cidr but a non-sensitive port: %+v", got)
	}
	if got := findingsFor(rule, "aws_security_group.range", resources); len(got) != 1 {
		t.Fatalf("a range that spans port 22 should still be caught: %+v", got)
	}
}

func TestSecurityGroupAllProtocolsFlagsAsBothSensitiveAndAllPorts(t *testing.T) {
	allProto := res("aws_security_group.all", "aws_security_group",
		ingress(map[string]any{"cidr_blocks": []any{"0.0.0.0/0"}, "from_port": float64(0), "to_port": float64(0), "protocol": "-1"}))
	resources := []planjson.Resource{allProto}

	sensitive := findingsFor(ruleByID("security-group-open-sensitive-port"), "aws_security_group.all", resources)
	if len(sensitive) != 1 {
		t.Fatalf("protocol -1 should trip the sensitive-port rule once (not once per port): %+v", sensitive)
	}
	allPorts := findingsFor(ruleByID("security-group-open-all-ports"), "aws_security_group.all", resources)
	if len(allPorts) != 1 {
		t.Fatalf("protocol -1 should trip the all-ports rule: %+v", allPorts)
	}
}

func TestSecurityGroupExplicitFullRangeAlsoTripsAllPorts(t *testing.T) {
	fullRange := res("aws_security_group.full", "aws_security_group",
		ingress(map[string]any{"cidr_blocks": []any{"0.0.0.0/0"}, "from_port": float64(0), "to_port": float64(65535), "protocol": "tcp"}))
	got := findingsFor(ruleByID("security-group-open-all-ports"), "aws_security_group.full", []planjson.Resource{fullRange})
	if len(got) != 1 {
		t.Fatalf("0-65535 tcp range: %+v", got)
	}
}

func TestSecurityGroupNarrowRangeDoesNotTripAllPorts(t *testing.T) {
	narrow := res("aws_security_group.narrow", "aws_security_group",
		ingress(map[string]any{"cidr_blocks": []any{"0.0.0.0/0"}, "from_port": float64(8000), "to_port": float64(9000), "protocol": "tcp"}))
	got := findingsFor(ruleByID("security-group-open-all-ports"), "aws_security_group.narrow", []planjson.Resource{narrow})
	if len(got) != 0 {
		t.Fatalf("a narrow open range is not all-ports: %+v", got)
	}
}

func TestSecurityGroupOpenToTheWholeIPv6Internet(t *testing.T) {
	// ::/0 is the IPv6 equivalent of 0.0.0.0/0; v0.1.0 read only IPv4.
	v6 := res("aws_security_group.v6", "aws_security_group",
		ingress(map[string]any{"cidr_blocks": []any{}, "ipv6_cidr_blocks": []any{"::/0"}, "from_port": float64(22), "to_port": float64(22), "protocol": "tcp"}))
	got := findingsFor(ruleByID("security-group-open-sensitive-port"), "aws_security_group.v6", []planjson.Resource{v6})
	if len(got) != 1 || got[0].Message != "ingress from ::/0 allows SSH (port 22)" {
		t.Fatalf("ipv6 ssh: %+v", got)
	}
}

func TestSplitIngressRuleResourceIsChecked(t *testing.T) {
	// aws_vpc_security_group_ingress_rule: one rule per resource, the
	// model the AWS provider now recommends. The finding names the rule
	// resource, since that is what has to change.
	pg := res("aws_vpc_security_group_ingress_rule.pg", "aws_vpc_security_group_ingress_rule",
		map[string]any{"cidr_ipv4": "0.0.0.0/0", "from_port": float64(5432), "to_port": float64(5432), "ip_protocol": "tcp"})
	https := res("aws_vpc_security_group_ingress_rule.https", "aws_vpc_security_group_ingress_rule",
		map[string]any{"cidr_ipv4": "0.0.0.0/0", "from_port": float64(443), "to_port": float64(443), "ip_protocol": "tcp"})
	fromSG := res("aws_vpc_security_group_ingress_rule.from_app", "aws_vpc_security_group_ingress_rule",
		map[string]any{"cidr_ipv4": nil, "referenced_security_group_id": "sg-123", "from_port": float64(5432), "to_port": float64(5432), "ip_protocol": "tcp"})
	resources := []planjson.Resource{pg, https, fromSG}
	rule := ruleByID("security-group-open-sensitive-port")

	if got := findingsFor(rule, "aws_vpc_security_group_ingress_rule.pg", resources); len(got) != 1 || got[0].Message != "ingress from 0.0.0.0/0 allows PostgreSQL (port 5432)" {
		t.Fatalf("split rule, open postgres: %+v", got)
	}
	if got := findingsFor(rule, "aws_vpc_security_group_ingress_rule.https", resources); len(got) != 0 {
		t.Fatalf("split rule, open 443 is not a sensitive port: %+v", got)
	}
	if got := findingsFor(rule, "aws_vpc_security_group_ingress_rule.from_app", resources); len(got) != 0 {
		t.Fatalf("split rule from another security group, no cidr: %+v", got)
	}
}

func TestSplitIngressRuleAllProtocolsOverIPv6(t *testing.T) {
	// ip_protocol "-1" leaves from_port/to_port null in the plan.
	all := res("aws_vpc_security_group_ingress_rule.all", "aws_vpc_security_group_ingress_rule",
		map[string]any{"cidr_ipv6": "::/0", "from_port": nil, "to_port": nil, "ip_protocol": "-1"})
	resources := []planjson.Resource{all}
	if got := findingsFor(ruleByID("security-group-open-all-ports"), "aws_vpc_security_group_ingress_rule.all", resources); len(got) != 1 {
		t.Fatalf("all protocols from ::/0: %+v", got)
	}
	if got := findingsFor(ruleByID("security-group-open-sensitive-port"), "aws_vpc_security_group_ingress_rule.all", resources); len(got) != 1 {
		t.Fatalf("all protocols should trip sensitive-port once: %+v", got)
	}
}

func TestLegacySecurityGroupRuleResourceIsChecked(t *testing.T) {
	in := res("aws_security_group_rule.ssh_in", "aws_security_group_rule",
		map[string]any{"type": "ingress", "cidr_blocks": []any{"0.0.0.0/0"}, "from_port": float64(22), "to_port": float64(22), "protocol": "tcp"})
	out := res("aws_security_group_rule.all_out", "aws_security_group_rule",
		map[string]any{"type": "egress", "cidr_blocks": []any{"0.0.0.0/0"}, "from_port": float64(0), "to_port": float64(0), "protocol": "-1"})
	resources := []planjson.Resource{in, out}
	if got := findingsFor(ruleByID("security-group-open-sensitive-port"), "aws_security_group_rule.ssh_in", resources); len(got) != 1 {
		t.Fatalf("legacy ingress rule, open ssh: %+v", got)
	}
	if got := findingsFor(ruleByID("security-group-open-all-ports"), "aws_security_group_rule.all_out", resources); len(got) != 0 {
		t.Fatalf("egress is not ingress: %+v", got)
	}
}
