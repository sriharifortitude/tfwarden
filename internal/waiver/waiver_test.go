package waiver

import (
	"strings"
	"testing"
	"time"

	"github.com/sriharifortitude/tfwarden/internal/rules"
)

func mustParse(t *testing.T, yaml string) *File {
	t.Helper()
	f, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	return f
}

func TestParseRequiresEveryField(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"missing rule", `waivers: [{resource: a, reason: r, expires: "2026-01-01"}]`, "waivers[0].rule"},
		{"missing resource", `waivers: [{rule: x, reason: r, expires: "2026-01-01"}]`, "waivers[0].resource"},
		{"missing reason", `waivers: [{rule: x, resource: a, expires: "2026-01-01"}]`, "waivers[0].reason"},
		{"missing expires", `waivers: [{rule: x, resource: a, reason: r}]`, "waivers[0].expires"},
		{"bad date", `waivers: [{rule: x, resource: a, reason: r, expires: "not-a-date"}]`, "not-a-date"},
		{"not yaml", `not: [valid`, "not valid YAML"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.yaml))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not mention %q", err.Error(), c.want)
			}
		})
	}
}

func TestApplyMatchesOnRuleAndResourceExactly(t *testing.T) {
	f := mustParse(t, `
waivers:
  - rule: s3-bucket-versioning-disabled
    resource: aws_s3_bucket.legacy
    reason: pre-dates the versioning requirement, migration ticket JIRA-42
    expires: "2027-01-01"
`)
	finding := rules.Finding{RuleID: "s3-bucket-versioning-disabled", Resource: "aws_s3_bucket.legacy", Status: rules.Fail}
	today := date(2026, 6, 1)

	outcome, entry := f.Apply(finding, today)
	if outcome != Waived || entry == nil {
		t.Fatalf("expected Waived, got %v", outcome)
	}

	otherResource := rules.Finding{RuleID: "s3-bucket-versioning-disabled", Resource: "aws_s3_bucket.other", Status: rules.Fail}
	if outcome, _ := f.Apply(otherResource, today); outcome != NotWaived {
		t.Fatalf("a waiver must not apply to a different resource: %v", outcome)
	}

	otherRule := rules.Finding{RuleID: "s3-bucket-encryption-missing", Resource: "aws_s3_bucket.legacy", Status: rules.Fail}
	if outcome, _ := f.Apply(otherRule, today); outcome != NotWaived {
		t.Fatalf("a waiver must not apply to a different rule on the same resource: %v", outcome)
	}
}

func TestApplyReportsExpiredSeparatelyFromWaived(t *testing.T) {
	f := mustParse(t, `
waivers:
  - rule: r1
    resource: a
    reason: temporary
    expires: "2026-01-01"
`)
	finding := rules.Finding{RuleID: "r1", Resource: "a"}

	if outcome, _ := f.Apply(finding, date(2025, 12, 31)); outcome != Waived {
		t.Fatalf("the day before expiry should still be waived, got %v", outcome)
	}
	if outcome, _ := f.Apply(finding, date(2026, 1, 1)); outcome != Waived {
		t.Fatalf("the expiry date itself should still be waived (After, not AfterOrEqual), got %v", outcome)
	}
	if outcome, _ := f.Apply(finding, date(2026, 1, 2)); outcome != Expired {
		t.Fatalf("the day after expiry should be Expired, not silently Waived, got %v", outcome)
	}
}

func date(y, m, d int) time.Time {
	return time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC)
}
