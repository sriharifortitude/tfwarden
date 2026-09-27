package rules

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/sriharifortitude/tfwarden/internal/planjson"
)

// A real `terraform show -json` plan (testdata/modules-and-count, see its
// generate.sh) with buckets in the two shapes v0.1.x could not link to
// their configuration: created with count, and inside a module called
// twice. Only module.bad's bucket lacks encryption, a public access block
// and versioning. v0.1.x reported 12 failures here, 9 of them false.
func TestRealPlanWithModulesAndCount(t *testing.T) {
	data, err := os.ReadFile("../../testdata/modules-and-count/plan.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := planjson.Parse(data)
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, f := range RunAll(p.Resources()) {
		got = append(got, string(f.Status)+" "+f.RuleID+" "+f.Resource)
	}
	sort.Strings(got)
	want := []string{
		"fail s3-bucket-encryption-missing module.bad.aws_s3_bucket.this",
		"fail s3-bucket-public-access-block-missing module.bad.aws_s3_bucket.this",
		"fail s3-bucket-versioning-disabled module.bad.aws_s3_bucket.this",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("findings:\n%s\n\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
