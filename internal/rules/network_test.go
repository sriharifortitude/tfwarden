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
