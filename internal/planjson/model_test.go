package planjson

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestParseRejectsNonPlanInput(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"not json", `not json at all`, "not valid JSON"},
		{"no format_version", `{"resource_changes": []}`, "does not look like"},
		{"wrong format major version", `{"format_version": "2.0"}`, "unsupported plan format_version"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.in))
			if err == nil {
				t.Fatal("expected an error, got none")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), c.want)
			}
		})
	}
}

func TestParseAcceptsAMinimalValidPlan(t *testing.T) {
	p, err := Parse([]byte(`{"format_version": "1.2", "terraform_version": "1.9.0", "resource_changes": [], "configuration": {"root_module": {}}}`))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if p.TerraformVersion != "1.9.0" {
		t.Fatalf("terraform_version = %q", p.TerraformVersion)
	}
}

const twoResourcePlan = `{
  "format_version": "1.2",
  "resource_changes": [
    {
      "address": "aws_s3_bucket.data",
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "data",
      "change": {"actions": ["create"], "after": {"bucket": "my-bucket"}, "after_unknown": {}}
    },
    {
      "address": "aws_s3_bucket_versioning.data",
      "mode": "managed",
      "type": "aws_s3_bucket_versioning",
      "name": "data",
      "change": {"actions": ["create"], "after": {"versioning_configuration": [{"status": "Enabled"}]}, "after_unknown": {}}
    },
    {
      "address": "aws_s3_bucket.old",
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "old",
      "change": {"actions": ["delete"], "after": null, "after_unknown": {}}
    },
    {
      "address": "data.aws_ami.ubuntu",
      "mode": "data",
      "type": "aws_ami",
      "name": "ubuntu",
      "change": {"actions": ["read"], "after": {"id": "ami-123"}, "after_unknown": {}}
    }
  ],
  "configuration": {
    "root_module": {
      "resources": [
        {
          "address": "aws_s3_bucket.data",
          "type": "aws_s3_bucket",
          "name": "data",
          "expressions": {"bucket": {"constant_value": "my-bucket"}}
        },
        {
          "address": "aws_s3_bucket_versioning.data",
          "type": "aws_s3_bucket_versioning",
          "name": "data",
          "expressions": {"bucket": {"references": ["aws_s3_bucket.data.id", "aws_s3_bucket.data"]}}
        }
      ],
      "module_calls": {
        "storage": {
          "module": {
            "resources": [
              {
                "address": "module.storage.aws_ebs_volume.extra",
                "type": "aws_ebs_volume",
                "name": "extra",
                "expressions": {"encrypted": {"constant_value": true}}
              }
            ]
          }
        }
      }
    }
  }
}`

func TestResourcesSkipsDestroysAndDataSources(t *testing.T) {
	p, err := Parse([]byte(twoResourcePlan))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	resources := p.Resources()
	if len(resources) != 2 {
		t.Fatalf("got %d resources, want 2 (the delete and the data source must be excluded): %+v", len(resources), resources)
	}
	for _, r := range resources {
		if r.Address == "aws_s3_bucket.old" || r.Address == "data.aws_ami.ubuntu" {
			t.Fatalf("resource %s should have been excluded", r.Address)
		}
	}
}

func TestResourceConfigIsAttachedByAddressIncludingInsideModules(t *testing.T) {
	p, err := Parse([]byte(twoResourcePlan))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	byAddr := Index(p.Resources())
	versioning, ok := byAddr["aws_s3_bucket_versioning.data"]
	if !ok || versioning.Config == nil {
		t.Fatalf("aws_s3_bucket_versioning.data should have a Config attached")
	}
	ref, ok := versioning.Config.Reference("bucket")
	if !ok || ref != "aws_s3_bucket.data" {
		t.Fatalf("Reference(bucket) = %q, %v; want aws_s3_bucket.data, true", ref, ok)
	}

	// The module-nested resource never appears in resource_changes in this
	// fixture (only the config side, to isolate collectConfig's recursion),
	// so we assert directly against the configuration tree instead of Resources().
	nested, ok := findConfigured(p.Configuration.RootModule, "module.storage.aws_ebs_volume.extra")
	if !ok {
		t.Fatal("module_calls recursion did not reach the nested resource")
	}
	if nested.Type != "aws_ebs_volume" {
		t.Fatalf("nested resource type = %q", nested.Type)
	}
}

func findConfigured(m ModuleConfig, addr string) (ResourceConfig, bool) {
	for _, r := range m.Resources {
		if r.Address == addr {
			return r, true
		}
	}
	for _, call := range m.ModuleCalls {
		if r, ok := findConfigured(call.Module, addr); ok {
			return r, true
		}
	}
	return ResourceConfig{}, false
}

func TestReferencePrefersTheBareResourceAddress(t *testing.T) {
	rc := ResourceConfig{Expressions: map[string]json.RawMessage{
		"bucket": json.RawMessage(`{"references": ["aws_s3_bucket.data.id", "aws_s3_bucket.data"]}`),
	}}
	ref, ok := rc.Reference("bucket")
	if !ok || ref != "aws_s3_bucket.data" {
		t.Fatalf("Reference = %q, %v", ref, ok)
	}
	if _, ok := rc.Reference("missing"); ok {
		t.Fatal("Reference on a missing key should be false")
	}
}

func TestDecodeUnknownFlattensNestedShapesToTheirTopLevelKey(t *testing.T) {
	unknown := decodeUnknown(json.RawMessage(`{"encrypted": true, "bucket": false, "versioning_configuration": [{"status": true}]}`))
	if !unknown["encrypted"] {
		t.Fatal("encrypted should be unknown")
	}
	if unknown["bucket"] {
		t.Fatal("bucket should be known (after_unknown false)")
	}
	if !unknown["versioning_configuration"] {
		t.Fatal("a nested unknown sub-attribute should mark the whole key unknown")
	}
}

func TestStripInstanceKeys(t *testing.T) {
	cases := map[string]string{
		"":                               "",
		"module.store":                   "module.store",
		"module.store[0]":                "module.store",
		`module.store["eu-west-1"]`:      "module.store",
		`module.a["x"].module.b[2]`:      "module.a.module.b",
		`module.odd["has]bracket"]`:      "module.odd",
		`module.esc["quote\"]inside"].x`: "module.esc.x",
		`aws_s3_bucket.logs["a"]`:        "aws_s3_bucket.logs",
	}
	for in, want := range cases {
		if got := stripInstanceKeys(in); got != want {
			t.Errorf("stripInstanceKeys(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInstanceKey(t *testing.T) {
	cases := []struct{ addr, typ, name, want string }{
		{"aws_s3_bucket.logs", "aws_s3_bucket", "logs", ""},
		{"aws_s3_bucket.logs[1]", "aws_s3_bucket", "logs", "[1]"},
		{`module.m["a"].aws_s3_bucket.logs["b"]`, "aws_s3_bucket", "logs", `["b"]`},
	}
	for _, c := range cases {
		r := Resource{Address: c.addr, Type: c.typ, Name: c.name}
		if got := r.InstanceKey(); got != c.want {
			t.Errorf("InstanceKey(%q) = %q, want %q", c.addr, got, c.want)
		}
	}
}

func TestUnknownAtLooksAtTheExactField(t *testing.T) {
	// The real after_unknown for an aws_s3_bucket_versioning with a literal
	// status: only the computed mfa_delete is unknown.
	r := Resource{UnknownTree: map[string]any{
		"versioning_configuration": []any{map[string]any{"mfa_delete": true}},
		"id":                       true,
	}}
	if r.UnknownAt("versioning_configuration", 0, "status") {
		t.Errorf("status is known; only its sibling mfa_delete is not")
	}
	if !r.UnknownAt("versioning_configuration", 0, "mfa_delete") {
		t.Errorf("mfa_delete is unknown")
	}
	if !r.UnknownAt("versioning_configuration") {
		t.Errorf("a block containing an unknown field counts as unknown when asked about as a whole")
	}
	if !r.UnknownAt("id") || r.UnknownAt("bucket") {
		t.Errorf("top-level: id unknown, bucket known")
	}

	whole := Resource{UnknownTree: map[string]any{"versioning_configuration": true}}
	if !whole.UnknownAt("versioning_configuration", 0, "status") {
		t.Errorf("an unknown ancestor makes the field under it unknown")
	}
}

func TestModuleResourcesGetConfigAndAbsoluteReferences(t *testing.T) {
	data, err := os.ReadFile("../../testdata/modules-and-count/plan.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	byAddr := Index(p.Resources())

	v, ok := byAddr["module.good.aws_s3_bucket_versioning.this[0]"]
	if !ok || v.Config == nil {
		t.Fatalf("module instance should have its configuration attached: %+v", v)
	}
	if v.ConfigAddress != "module.good.aws_s3_bucket_versioning.this" {
		t.Errorf("ConfigAddress = %q", v.ConfigAddress)
	}
	if ref, _ := v.Config.Reference("bucket"); ref != "module.good.aws_s3_bucket.this" {
		t.Errorf("reference inside module.good should resolve absolutely, got %q", ref)
	}

	// The same module is called twice; each call's config must stay its own.
	b, ok := byAddr["module.bad.aws_s3_bucket.this"]
	if !ok || b.Config == nil || b.Config.ModulePath != "module.bad" {
		t.Fatalf("module.bad's bucket should carry module.bad's config: %+v", b.Config)
	}

	c, ok := byAddr["aws_s3_bucket_versioning.counted[1]"]
	if !ok || c.Config == nil || c.ConfigAddress != "aws_s3_bucket_versioning.counted" {
		t.Fatalf("a count instance should find its configuration block: %+v", c)
	}
}
