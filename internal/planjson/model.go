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
	"strings"
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

	// ModulePath is where this block sits, e.g. "module.store" ("" at the
	// root). Addresses and references inside a module's configuration are
	// relative to it; this is what makes them absolute.
	ModulePath string `json:"-"`
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
	return joinAddress(rc.ModulePath, ref), true
}

func joinAddress(modulePath, addr string) string {
	if modulePath == "" {
		return addr
	}
	return modulePath + "." + addr
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

	// ConfigAddress is the address of the configuration block this instance
	// came from: Address with every module and resource instance key
	// removed. module.store["a"].aws_s3_bucket.this[0] and [1] both have
	// ConfigAddress module.store.aws_s3_bucket.this, the form a reference in
	// another block's configuration resolves to.
	ConfigAddress string

	// UnknownTree is after_unknown exactly as Terraform wrote it. Unknown
	// flattens it to one bool per top-level key, which is right for scalar
	// attributes but wrong for a nested block: one computed sub-field (S3
	// versioning's mfa_delete) would make the whole block, including a
	// status written literally in the config, look unknown. Use UnknownAt
	// for anything inside a block.
	UnknownTree any
}

// ConfigAddr is ConfigAddress, or Address for a Resource built by hand
// without one (as rule unit tests do).
func (r Resource) ConfigAddr() string {
	if r.ConfigAddress != "" {
		return r.ConfigAddress
	}
	return r.Address
}

// InstanceKey is the trailing [index] or ["key"] of Address, or "" for a
// resource without count or for_each.
func (r Resource) InstanceKey() string {
	i := strings.LastIndex(r.Address, r.Type+"."+r.Name)
	if i < 0 {
		return ""
	}
	return r.Address[i+len(r.Type)+1+len(r.Name):]
}

// UnknownAt reports whether the value at path is not known until apply.
// Path steps are map keys (string) and list positions (int). An unknown
// ancestor makes everything under it unknown; at the end of the path, a
// subtree containing any unknown counts as unknown.
func (r Resource) UnknownAt(path ...any) bool {
	if r.UnknownTree == nil && len(path) > 0 {
		// Built by hand with only the flattened map (rule unit tests):
		// fall back to its top-level answer.
		key, _ := path[0].(string)
		return r.Unknown[key]
	}
	node := r.UnknownTree
	for _, step := range path {
		switch n := node.(type) {
		case bool:
			return n
		case map[string]any:
			key, _ := step.(string)
			node = n[key]
		case []any:
			i, ok := step.(int)
			if !ok || i < 0 || i >= len(n) {
				return false
			}
			node = n[i]
		default:
			return false // nothing recorded here: known
		}
	}
	return containsUnknown(node)
}

func containsUnknown(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case map[string]any:
		for _, e := range x {
			if containsUnknown(e) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if containsUnknown(e) {
				return true
			}
		}
	}
	return false
}

// Resources returns every managed resource being created or updated
// (never a pure delete, and never a data source, which nothing "creates"
// for a rule to check) as a flat list regardless of module nesting.
func (p *Plan) Resources() []Resource {
	byAddr := map[string]*ResourceConfig{}
	collectConfig(p.Configuration.RootModule, "", byAddr)

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
		configAddr := joinAddress(stripInstanceKeys(rc.ModuleAddr), rc.Type+"."+rc.Name)
		var unknownTree any
		if len(rc.Change.AfterUnknown) > 0 {
			_ = json.Unmarshal(rc.Change.AfterUnknown, &unknownTree) // malformed: treat as nothing unknown, as decodeUnknown does
		}
		r := Resource{Address: rc.Address, Type: rc.Type, Name: rc.Name, After: after, Unknown: unknown, ConfigAddress: configAddr, UnknownTree: unknownTree}
		// Looked up by configuration address, not instance address: v0.1.x
		// used rc.Address here, which never matched a resource inside a
		// module (module.x. prefix) or one with count/for_each ([0] suffix),
		// so every such resource looked as if nothing referenced it.
		if cfg, ok := byAddr[configAddr]; ok {
			r.Config = cfg
		}
		out = append(out, r)
	}
	return out
}

func collectConfig(m ModuleConfig, modulePath string, out map[string]*ResourceConfig) {
	for i := range m.Resources {
		cfg := &m.Resources[i]
		cfg.ModulePath = modulePath
		out[joinAddress(modulePath, cfg.Address)] = cfg
	}
	for name, call := range m.ModuleCalls {
		collectConfig(call.Module, joinAddress(modulePath, "module."+name), out)
	}
}

// stripInstanceKeys removes every [index] or ["key"] from an address,
// respecting quotes, since a for_each key is a string that may itself
// contain "]".
func stripInstanceKeys(addr string) string {
	var b strings.Builder
	depth, quoted := 0, false
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		switch {
		case depth > 0 && quoted && c == '\\' && i+1 < len(addr):
			i++ // skip the escaped character
		case depth > 0 && c == '"':
			quoted = !quoted
		case !quoted && c == '[':
			depth++
		case !quoted && c == ']' && depth > 0:
			depth--
		case depth == 0:
			b.WriteByte(c)
		}
	}
	return b.String()
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
