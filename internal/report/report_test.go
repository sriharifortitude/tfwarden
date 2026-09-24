package report

import (
	"strings"
	"testing"

	"github.com/sriharifortitude/tfwarden/internal/rules"
	"github.com/sriharifortitude/tfwarden/internal/waiver"
)

func sample() Result {
	return NewResult([]Row{
		{Finding: rules.Finding{RuleID: "s3-bucket-public-acl", Severity: rules.Critical, Resource: "aws_s3_bucket_acl.public", Status: rules.Fail, Message: `acl = "public-read"`, Remediation: "use private"}},
		{Finding: rules.Finding{RuleID: "s3-bucket-versioning-disabled", Severity: rules.Medium, Resource: "aws_s3_bucket.legacy", Status: rules.Fail, Message: "no versioning"},
			WaiverOutcome: waiver.Waived, Waiver: &waiver.Entry{Reason: "migration ticket JIRA-42", Expires: "2027-01-01"}},
		{Finding: rules.Finding{RuleID: "rds-storage-unencrypted", Severity: rules.High, Resource: "aws_db_instance.old", Status: rules.Fail, Message: "storage_encrypted = false"},
			WaiverOutcome: waiver.Expired, Waiver: &waiver.Entry{Reason: "was meant to be temporary", Expires: "2025-01-01"}},
		{Finding: rules.Finding{RuleID: "ebs-volume-unencrypted", Severity: rules.High, Resource: "aws_ebs_volume.pending", Status: rules.Indeterminate, Message: "depends on a KMS key not yet created"}},
	})
}

func TestCountsClassifyEveryRowExactlyOnce(t *testing.T) {
	// Counts is the human-readable summary: every row lands in exactly one
	// bucket (Indeterminate > Expired > Waived > Fail), so the four numbers
	// sum to the row count. The expired-waiver row is its own bucket here,
	// even though it still counts toward Failing() for the exit code --
	// that's a different question ("what should I look at" vs "should CI fail").
	c := sample().Counts()
	if c.Fail != 1 { // only the plain acl finding; the expired-waiver row is its own bucket
		t.Fatalf("Fail = %d, want 1", c.Fail)
	}
	if c.Waived != 1 {
		t.Fatalf("Waived = %d, want 1", c.Waived)
	}
	if c.ExpiredWaiver != 1 {
		t.Fatalf("ExpiredWaiver = %d, want 1", c.ExpiredWaiver)
	}
	if c.Indeterminate != 1 {
		t.Fatalf("Indeterminate = %d, want 1", c.Indeterminate)
	}
}

func TestFailingExcludesWaivedIndeterminateAndBelowThreshold(t *testing.T) {
	r := sample()
	failing := r.Failing(rules.Low)
	// acl (Critical) and the expired-waiver rds finding (High) fail; the
	// waived versioning finding and the Indeterminate ebs finding do not.
	if len(failing) != 2 {
		t.Fatalf("Failing(Low) = %d rows, want 2: %+v", len(failing), failing)
	}
	onlyCritical := r.Failing(rules.Critical)
	if len(onlyCritical) != 1 || onlyCritical[0].RuleID != "s3-bucket-public-acl" {
		t.Fatalf("Failing(Critical) = %+v", onlyCritical)
	}
}

func TestTerminalNamesExpiredWaiversDifferentlyFromActiveOnes(t *testing.T) {
	text := Terminal(sample())
	if !strings.Contains(text, "WAIVER EXPIRED") {
		t.Fatal("expired waiver should be called out distinctly, not blended in as 'waived'")
	}
	if !strings.Contains(text, "waived 2027-01-01: migration ticket JIRA-42") {
		t.Fatalf("active waiver line missing or wrong shape:\n%s", text)
	}
	if !strings.Contains(text, "4 findings: 1 failing, 1 waived, 1 expired waivers, 1 indeterminate") {
		t.Fatalf("summary line missing or wrong:\n%s", text)
	}
	if strings.Contains(text[strings.Index(text, "no versioning"):strings.Index(text, "no versioning")+120], "fix:") {
		t.Fatal("a waived finding should not show a remediation instruction")
	}
}

func TestJSONRoundTripsTheWaiverNote(t *testing.T) {
	b, err := JSON(sample())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	s := string(b)
	if !strings.Contains(s, `"waived": true`) {
		t.Fatal("waived row should have waived: true")
	}
	if !strings.Contains(s, "migration ticket JIRA-42 (expires 2027-01-01)") {
		t.Fatalf("waiver_note missing:\n%s", s)
	}
	if !strings.Contains(s, `"status": "indeterminate"`) {
		t.Fatal("indeterminate status should be preserved as its own value, not folded into pass/fail")
	}
}

func TestSarifOmitsWaivedFindingsButKeepsExpiredAndDeclaresEveryRule(t *testing.T) {
	b, err := SARIF(sample())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	s := string(b)
	if strings.Contains(s, "migration ticket") {
		t.Fatal("a waived finding must not appear in SARIF results")
	}
	if !strings.Contains(s, "storage_encrypted = false") {
		t.Fatal("an expired waiver must still appear in SARIF as a real finding")
	}
	if !strings.Contains(s, `"ruleId": "s3-bucket-public-acl"`) {
		t.Fatal("the critical finding should be present")
	}
	// The driver declares all ten built-in rules regardless of how many fired.
	if strings.Count(s, `"shortDescription"`) != len(rules.All()) {
		t.Fatalf("expected %d declared rules, SARIF has %d shortDescription entries", len(rules.All()), strings.Count(s, `"shortDescription"`))
	}
	if !strings.Contains(s, `"level": "error"`) {
		t.Fatal("Critical/High findings should map to SARIF level error")
	}
}
