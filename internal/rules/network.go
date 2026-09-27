package rules

import (
	"strconv"

	"github.com/sriharifortitude/tfwarden/internal/planjson"
)

func init() {
	register(sgOpenSensitivePort{})
	register(sgOpenAllPorts{})
}

// sensitivePorts are the ones a security-group rule opened to the whole
// internet is almost never intentional. Named for the message, not just numbers.
var sensitivePorts = []struct {
	Port int
	Name string
}{
	{22, "SSH"},
	{3389, "RDP"},
	{3306, "MySQL"},
	{5432, "PostgreSQL"},
	{6379, "Redis"},
	{27017, "MongoDB"},
}

// openCIDRs are the two ways to say "the whole internet". v0.1.0 checked
// only the IPv4 one, so ::/0 passed.
var openCIDRs = map[string]bool{"0.0.0.0/0": true, "::/0": true}

// inboundRule is one inbound rule, normalised from whichever of the three
// shapes Terraform lets you write it in:
//   - an inline ingress block on aws_security_group
//   - an aws_security_group_rule with type = "ingress"
//   - an aws_vpc_security_group_ingress_rule (one rule per resource, the
//     shape the AWS provider now recommends)
//
// Resource is the address of whatever has to change to fix it: the rule
// resource for the split shapes, the security group for inline blocks.
type inboundRule struct {
	Resource   string
	CIDR       string // the open CIDR that matched
	Protocol   string
	From, To   int
	PortsKnown bool
}

// openInbound returns every inbound rule whose source is the whole internet.
// A rule whose source is not known until apply is skipped, not guessed.
func openInbound(resources []planjson.Resource) []inboundRule {
	var out []inboundRule
	for _, r := range resources {
		switch r.Type {
		case "aws_security_group":
			blocks, known := inlineIngress(r)
			if !known {
				continue
			}
			for _, b := range blocks {
				if cidr := firstOpen(b["cidr_blocks"], b["ipv6_cidr_blocks"]); cidr != "" {
					out = append(out, newInbound(r.Address, cidr, b["protocol"], b["from_port"], b["to_port"]))
				}
			}
		case "aws_security_group_rule":
			if typ, known := stringAttr(r, "type"); !known || typ != "ingress" {
				continue
			}
			v4, _ := attr(r, "cidr_blocks")
			v6, _ := attr(r, "ipv6_cidr_blocks")
			if cidr := firstOpen(v4, v6); cidr != "" {
				out = append(out, newInbound(r.Address, cidr, r.After["protocol"], r.After["from_port"], r.After["to_port"]))
			}
		case "aws_vpc_security_group_ingress_rule":
			v4, _ := attr(r, "cidr_ipv4")
			v6, _ := attr(r, "cidr_ipv6")
			if cidr := firstOpen(v4, v6); cidr != "" {
				out = append(out, newInbound(r.Address, cidr, r.After["ip_protocol"], r.After["from_port"], r.After["to_port"]))
			}
		}
	}
	return out
}

func newInbound(address, cidr string, protocol, from, to any) inboundRule {
	p, _ := protocol.(string)
	f, okf := from.(float64)
	t, okt := to.(float64)
	return inboundRule{Resource: address, CIDR: cidr, Protocol: p, From: int(f), To: int(t), PortsKnown: okf && okt}
}

// inlineIngress reads the inline ingress blocks of an aws_security_group.
func inlineIngress(r planjson.Resource) ([]map[string]any, bool) {
	v, ok := attr(r, "ingress")
	if !ok {
		return nil, false
	}
	list, isList := v.([]any)
	if !isList {
		return nil, false
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out, true
}

// firstOpen returns the first whole-internet CIDR among values that may each
// be a single CIDR string or a list of them, or "" if there is none. One
// rule open over both IPv4 and IPv6 is still one finding.
func firstOpen(values ...any) string {
	for _, v := range values {
		switch x := v.(type) {
		case string:
			if openCIDRs[x] {
				return x
			}
		case []any:
			for _, c := range x {
				if s, ok := c.(string); ok && openCIDRs[s] {
					return s
				}
			}
		}
	}
	return ""
}

// allProtocols reports the "every protocol, every port" wildcard: "-1",
// which aws_security_group_rule also accepts spelled "all". When it is set
// the port range in the plan is 0/0 or null and carries no information, so
// the protocol is checked on its own rather than folded into 0-65535.
func allProtocols(r inboundRule) bool {
	return r.Protocol == "-1" || r.Protocol == "all"
}

type sgOpenSensitivePort struct{}

func (sgOpenSensitivePort) ID() string         { return "security-group-open-sensitive-port" }
func (sgOpenSensitivePort) Severity() Severity { return Critical }
func (sgOpenSensitivePort) Description() string {
	return "a security group allows inbound traffic from the whole internet on a database or remote-access port"
}

func (rule sgOpenSensitivePort) Check(resources []planjson.Resource, _ map[string]planjson.Resource) []Finding {
	var out []Finding
	for _, in := range openInbound(resources) {
		if allProtocols(in) {
			out = append(out, Finding{
				RuleID: rule.ID(), Severity: rule.Severity(), Resource: in.Resource, Status: Fail,
				Message:     "ingress from " + in.CIDR + " with protocol \"-1\" (all protocols) covers every sensitive port too",
				Remediation: "restrict the source to known ranges, or front this with a bastion / VPN",
			})
			continue
		}
		if !in.PortsKnown {
			continue
		}
		for _, sp := range sensitivePorts {
			if in.From <= sp.Port && sp.Port <= in.To {
				out = append(out, Finding{
					RuleID: rule.ID(), Severity: rule.Severity(), Resource: in.Resource, Status: Fail,
					Message:     "ingress from " + in.CIDR + " allows " + sp.Name + " (port " + strconv.Itoa(sp.Port) + ")",
					Remediation: "restrict the source to known ranges, or front this with a bastion / VPN",
				})
			}
		}
	}
	return out
}

type sgOpenAllPorts struct{}

func (sgOpenAllPorts) ID() string         { return "security-group-open-all-ports" }
func (sgOpenAllPorts) Severity() Severity { return Critical }
func (sgOpenAllPorts) Description() string {
	return "a security group allows all inbound traffic from the whole internet"
}

func (rule sgOpenAllPorts) Check(resources []planjson.Resource, _ map[string]planjson.Resource) []Finding {
	var out []Finding
	for _, in := range openInbound(resources) {
		spansAllPorts := in.PortsKnown && in.From <= 0 && in.To >= 65535
		if allProtocols(in) || spansAllPorts {
			out = append(out, Finding{
				RuleID: rule.ID(), Severity: rule.Severity(), Resource: in.Resource, Status: Fail,
				Message:     "ingress from " + in.CIDR + " spans every port (protocol \"-1\" or a 0-65535 range): every port is open to the internet",
				Remediation: "list only the specific ports this service needs",
			})
		}
	}
	return out
}
