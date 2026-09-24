package planjson

import (
	"encoding/json"
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
