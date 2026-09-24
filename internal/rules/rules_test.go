package rules

import (
	"encoding/json"
	"testing"

	"github.com/sriharifortitude/tfwarden/internal/planjson"
)

// res is a small builder for hand-written test resources. Building these
// directly avoids depending on the plan JSON schema being exactly right
// in every test -- that schema is covered separately in the planjson
// package and in the one end-to-end CLI test.
func res(addr, typ string, after map[string]any) planjson.Resource {
	name := addr
	if i := lastDot(addr); i >= 0 {
		name = addr[i+1:]
	}
	return planjson.Resource{Address: addr, Type: typ, Name: name, After: after, Unknown: map[string]bool{}}
}

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}

func withUnknown(r planjson.Resource, keys ...string) planjson.Resource {
	r.Unknown = map[string]bool{}
	for _, k := range keys {
		r.Unknown[k] = true
	}
	return r
}

// withConfig attaches a Config whose expressions map an attribute name to
// the resource address it symbolically references -- the shape a rule's
// findReferencing/Reference lookup reads.
func withConfig(r planjson.Resource, expressions map[string]string) planjson.Resource {
	exprs := map[string]json.RawMessage{}
	for attrName, target := range expressions {
		exprs[attrName] = json.RawMessage(`{"references": ["` + target + `.id", "` + target + `"]}`)
	}
	r.Config = &planjson.ResourceConfig{Address: r.Address, Type: r.Type, Name: r.Name, Expressions: exprs}
	return r
}

func findingsFor(rule Rule, addr string, resources []planjson.Resource) []Finding {
	byAddr := planjson.Index(resources)
	var out []Finding
	for _, f := range rule.Check(resources, byAddr) {
		if f.Resource == addr {
			out = append(out, f)
		}
	}
	return out
}

func ruleByID(id string) Rule {
	for _, r := range All() {
		if r.ID() == id {
			return r
		}
	}
	panic("no such rule: " + id)
}

func TestRegistryHasNoDuplicateIDs(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range All() {
		if seen[r.ID()] {
			t.Fatalf("duplicate rule ID %q", r.ID())
		}
		seen[r.ID()] = true
	}
	if len(registry) != 10 {
		t.Fatalf("expected 10 built-in rules, got %d: %v", len(registry), idsOf(registry))
	}
}

func idsOf(rs []Rule) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.ID()
	}
	return out
}
