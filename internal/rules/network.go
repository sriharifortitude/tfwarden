package rules

import (
	"strconv"

	"github.com/sriharifortitude/tfwarden/internal/planjson"
)

func init() {
	register(sgOpenSensitivePort{})
	register(sgOpenAllPorts{})
}

const openCIDR = "0.0.0.0/0"

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

// ingressRules reads the classic inline `ingress` blocks of an
// aws_security_group. The newer split-resource model
// (aws_vpc_security_group_ingress_rule, one rule per resource) is not
// covered -- see the README's "what it does not do".
func ingressRules(r planjson.Resource) ([]map[string]any, bool) {
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

func cidrsOpen(rule map[string]any) bool {
	v, ok := rule["cidr_blocks"]
	if !ok {
		return false
	}
	list, ok := v.([]any)
	if !ok {
		return false
	}
	for _, c := range list {
		if s, ok := c.(string); ok && s == openCIDR {
			return true
		}
	}
	return false
}

func portRange(rule map[string]any) (from, to int, ok bool) {
	f, okf := rule["from_port"].(float64)
	t, okt := rule["to_port"].(float64)
	if !okf || !okt {
		return 0, 0, false
	}
	return int(f), int(t), true
}

// allProtocols reports protocol = "-1", AWS's "every protocol, every
// port" wildcard. When set, the port range in the plan is typically 0/0
// and carries no information -- the protocol field is what actually
// says "everything", so it is checked on its own rather than folded
// into portRange's 0-65535 comparison.
func allProtocols(rule map[string]any) bool {
	p, ok := rule["protocol"].(string)
	return ok && p == "-1"
}

type sgOpenSensitivePort struct{}

func (sgOpenSensitivePort) ID() string         { return "security-group-open-sensitive-port" }
func (sgOpenSensitivePort) Severity() Severity { return Critical }
func (sgOpenSensitivePort) Description() string {
	return "a security group allows inbound traffic from 0.0.0.0/0 on a database or remote-access port"
}

func (rule sgOpenSensitivePort) Check(resources []planjson.Resource, _ map[string]planjson.Resource) []Finding {
	var out []Finding
	for _, r := range resources {
		if r.Type != "aws_security_group" {
			continue
		}
		rules, known := ingressRules(r)
		if !known {
			continue
		}
		for _, ing := range rules {
			if !cidrsOpen(ing) {
				continue
			}
			if allProtocols(ing) {
				out = append(out, Finding{
					RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Fail,
					Message:     "ingress from 0.0.0.0/0 with protocol \"-1\" (all protocols) covers every sensitive port too",
					Remediation: "restrict cidr_blocks to known ranges, or front this with a bastion / VPN",
				})
				continue
			}
			from, to, portsKnown := portRange(ing)
			if !portsKnown {
				continue
			}
			for _, sp := range sensitivePorts {
				if from <= sp.Port && sp.Port <= to {
					out = append(out, Finding{
						RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Fail,
						Message:     "ingress from 0.0.0.0/0 allows " + sp.Name + " (port " + strconv.Itoa(sp.Port) + ")",
						Remediation: "restrict cidr_blocks to known ranges, or front this with a bastion / VPN",
					})
				}
			}
		}
	}
	return out
}

type sgOpenAllPorts struct{}

func (sgOpenAllPorts) ID() string         { return "security-group-open-all-ports" }
func (sgOpenAllPorts) Severity() Severity { return Critical }
func (sgOpenAllPorts) Description() string {
	return "a security group allows all inbound traffic from 0.0.0.0/0"
}

func (rule sgOpenAllPorts) Check(resources []planjson.Resource, _ map[string]planjson.Resource) []Finding {
	var out []Finding
	for _, r := range resources {
		if r.Type != "aws_security_group" {
			continue
		}
		rules, known := ingressRules(r)
		if !known {
			continue
		}
		for _, ing := range rules {
			if !cidrsOpen(ing) {
				continue
			}
			from, to, portsKnown := portRange(ing)
			spansAllPorts := portsKnown && from <= 0 && to >= 65535
			if allProtocols(ing) || spansAllPorts {
				out = append(out, Finding{
					RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Fail,
					Message:     "ingress from 0.0.0.0/0 spans every port (protocol \"-1\" or a 0-65535 range): every port is open to the internet",
					Remediation: "list only the specific ports this service needs",
				})
			}
		}
	}
	return out
}
