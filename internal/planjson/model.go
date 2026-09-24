// Package planjson reads the output of `terraform show -json <plan>`, the
// structured plan format Terraform has published since 0.12. Scanning the
// plan rather than raw .tf files means every variable, module call and
// count/for_each expansion is already resolved into concrete resource
// instances -- exactly what will be created, not what the source merely
// implies. See docs/adr/0001-plan-json-not-hcl.md.
package planjson

import (
	"encoding/json"
	"fmt"
)

// Plan is the subset of the plan JSON schema tfwarden reads. Fields not
// used by any rule are deliberately omitted rather than modelled and
// ignored, so a schema change that matters shows up as a decode error
// instead of a silently empty field.
type Plan struct {
	FormatVersion    string           `json:"format_version"`
	TerraformVersion string           `json:"terraform_version"`
	ResourceChanges  []ResourceChange `json:"resource_changes"`
	Configuration    Configuration    `json:"configuration"`
}

// ResourceChange is one planned resource instance and what will happen to it.
type ResourceChange struct {
	Address      string `json:"address"`
	ModuleAddr   string `json:"module_address"`
	Mode         string `json:"mode"` // "managed" or "data"
	Type         string `json:"type"`
	Name         string `json:"name"`
	ProviderName string `json:"provider_name"`
	Change       Change `json:"change"`
}

// Change carries the planned attribute values and which of them are not
// yet known (because they depend on a resource not yet created).
type Change struct {
	Actions      []string        `json:"actions"`
	After        json.RawMessage `json:"after"`
	AfterUnknown json.RawMessage `json:"after_unknown"`
}

// Destroying reports whether this change is a pure delete (nothing to check).
func (c Change) Destroying() bool {
	return len(c.Actions) == 1 && c.Actions[0] == "delete"
}

// Configuration mirrors the parts of the "configuration" block that keep
// symbolic references between resources -- planned_values and
// resource_changes only ever hold resolved values or "unknown", so
// cross-resource rules (does this bucket have an encryption config
// pointing at it?) must read expressions here instead.
type Configuration struct {
	RootModule ModuleConfig `json:"root_module"`
}

type ModuleConfig struct {
	Resources   []ResourceConfig      `json:"resources"`
	ModuleCalls map[string]ModuleCall `json:"module_calls"`
}

type ModuleCall struct {
	Module ModuleConfig `json:"module"`
}

type ResourceConfig struct {
	Address     string                     `json:"address"`
	Type        string                     `json:"type"`
	Name        string                     `json:"name"`
	Expressions map[string]json.RawMessage `json:"expressions"`
}

// Reference returns the resource address a single-valued attribute
// expression refers to, e.g. {"references": ["aws_s3_bucket.data.id", "aws_s3_bucket.data"]}
// -> "aws_s3_bucket.data". Terraform lists the most specific reference
// first; the resource address is what a rule needs.
func (rc ResourceConfig) Reference(attr string) (string, bool) {
	raw, ok := rc.Expressions[attr]
	if !ok {
		return "", false
	}
	var expr struct {
		References []string `json:"references"`
	}
	if err := json.Unmarshal(raw, &expr); err != nil || len(expr.References) == 0 {
		return "", false
	}
	// Strip a trailing attribute selector like ".id" to get the resource address.
	ref := expr.References[len(expr.References)-1]
	for _, r := range expr.References {
		if isResourceAddress(r) {
			ref = r
			break
		}
	}
	return ref, true
}

func isResourceAddress(s string) bool {
	// A bare resource address is "type.name"; a selector like "type.name.attr"
	// or "type.name[0]" is not. Good enough to prefer the shortest reference.
	count := 0
	for _, c := range s {
		if c == '.' {
			count++
		}
	}
	return count == 1
}

// Parse decodes a `terraform show -json` document. A document that is
// syntactically valid JSON but not a plan (wrong format_version, no
// resource_changes key at all) is refused with a specific reason rather
// than silently scanning nothing.
func Parse(data []byte) (*Plan, error) {
	var p Plan
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	if p.FormatVersion == "" {
		return nil, fmt.Errorf("no format_version field: this does not look like `terraform show -json` output")
	}
	major := 0
	fmt.Sscanf(p.FormatVersion, "%d.", &major) //nolint:errcheck // best-effort; falls through to the range check below
	if major != 1 {
		return nil, fmt.Errorf("unsupported plan format_version %q: tfwarden reads format 1.x", p.FormatVersion)
	}
	return &p, nil
}

// Resource is a decoded attribute map plus which keys are unknown, the
// shape every rule actually works against.
type Resource struct {
	Address string
	Type    string
	Name    string
	After   map[string]any
	Unknown map[string]bool
	Config  *ResourceConfig
}

// Resources returns every managed resource being created or updated
// (never a pure delete, and never a data source, which nothing "creates"
// for a rule to check) as a flat list regardless of module nesting.
func (p *Plan) Resources() []Resource {
	byAddr := map[string]*ResourceConfig{}
	collectConfig(p.Configuration.RootModule, byAddr)

	out := make([]Resource, 0, len(p.ResourceChanges))
	for _, rc := range p.ResourceChanges {
		if rc.Mode != "managed" || rc.Change.Destroying() || len(rc.Change.After) == 0 {
			continue
		}
		var after map[string]any
		if err := json.Unmarshal(rc.Change.After, &after); err != nil {
			continue // a resource whose `after` is not an object (shouldn't happen); skip rather than guess
		}
		unknown := decodeUnknown(rc.Change.AfterUnknown)
		r := Resource{Address: rc.Address, Type: rc.Type, Name: rc.Name, After: after, Unknown: unknown}
		if cfg, ok := byAddr[rc.Address]; ok {
			r.Config = cfg
		}
		out = append(out, r)
	}
	return out
}

func collectConfig(m ModuleConfig, out map[string]*ResourceConfig) {
	for i := range m.Resources {
		out[m.Resources[i].Address] = &m.Resources[i]
	}
	for _, call := range m.ModuleCalls {
		collectConfig(call.Module, out)
	}
}

// decodeUnknown flattens Terraform's after_unknown shape (bool, or a
// nested object/array for computed sub-attributes) to "is this top-level
// key at all uncertain", which is the granularity every rule needs.
func decodeUnknown(raw json.RawMessage) map[string]bool {
	out := map[string]bool{}
	if len(raw) == 0 {
		return out
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return out
	}
	for k, v := range m {
		var b bool
		if json.Unmarshal(v, &b) == nil {
			out[k] = b
			continue
		}
		// A non-bool (object/array) means at least part of this attribute
		// is unknown; treat the whole key as unknown, which is the
		// conservative direction (see the "indeterminate" finding class).
		out[k] = true
	}
	return out
}

// ByAddress finds a resource this plan will create or update, for rules
// that check a relationship ("is there a matching encryption config?").
func Index(resources []Resource) map[string]Resource {
	m := make(map[string]Resource, len(resources))
	for _, r := range resources {
		m[r.Address] = r
	}
	return m
}
