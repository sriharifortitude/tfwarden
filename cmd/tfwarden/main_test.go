package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// out runs the CLI in-process (real flag parsing, real file I/O, real
// rules and waiver application) and returns the exit code plus whatever
// was written to --output.
func out(t *testing.T, args ...string) (code int, report string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "report.out")
	// --output must come before the positional plan-file argument: the
	// flag package stops parsing flags at the first non-flag token, so
	// args[0] (the subcommand) stays first and everything else after it
	// is inserted ahead of whatever positional argument the test passed.
	withOutput := append([]string{args[0], "--output", path}, args[1:]...)
	code = run(withOutput)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return code, ""
		}
		t.Fatalf("reading report: %s", err)
	}
	return code, string(data)
}

func TestScanTheSmallFixtureWithoutWaivers(t *testing.T) {
	code, report := out(t, "scan", "--format", "json", "../../testdata/small-plan.json")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (four real findings, none waived)", code)
	}
	for _, want := range []string{
		`"rule": "s3-bucket-encryption-missing"`,
		`"rule": "s3-bucket-public-access-block-missing"`,
		`"rule": "s3-bucket-versioning-disabled"`,
		`"rule": "security-group-open-sensitive-port"`,
		`"resource": "aws_s3_bucket.legacy"`,
		`"resource": "aws_security_group.web"`,
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %s\n%s", want, report)
		}
	}
	if strings.Contains(report, "aws_s3_bucket.clean") {
		t.Error("the clean bucket has full protection and should produce nothing")
	}
	summary := `"fail": 4`
	if !strings.Contains(report, summary) {
		t.Errorf("report missing %s\n%s", summary, report)
	}
}

func TestScanTheSmallFixtureWithWaivers(t *testing.T) {
	code, report := out(t, "scan", "--format", "json", "--waivers", "../../testdata/waivers.yaml", "../../testdata/small-plan.json")
	// The active waiver removes one Fail from the count; the expired one
	// still fails the run, so exit code stays 1.
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (the expired waiver still fails the gate)", code)
	}
	if !strings.Contains(report, `"waived": true`) {
		t.Error("the active waiver should mark its row waived: true")
	}
	if !strings.Contains(report, "migration ticket JIRA-42") {
		t.Error("the active waiver's reason should be in the report")
	}
	if !strings.Contains(report, "was meant to be temporary") {
		t.Error("the expired waiver's reason should still be visible (it is why the finding is back)")
	}
	if !strings.Contains(report, `"fail": 2`) {
		// encryption-missing + public-access-block-missing on the legacy bucket;
		// versioning-disabled is actively waived, sensitive-port is its own
		// expired-waiver bucket in the summary (see report.Counts doc comment).
		t.Errorf("report:\n%s", report)
	}
}

func TestScanTheSmallFixtureWithAHighFailOnThreshold(t *testing.T) {
	// medium (versioning-disabled) and high (encryption-missing) drop below
	// the bar; the two Critical findings (public-access-block-missing,
	// sensitive-port) still fail the run.
	code, _ := out(t, "scan", "--format", "json", "--fail-on", "critical", "../../testdata/small-plan.json")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (two Critical findings remain)", code)
	}
}

func TestScanTheCleanFixtureExitsZero(t *testing.T) {
	code, report := out(t, "scan", "--format", "json", "../../testdata/clean-plan.json")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", code, report)
	}
	if !strings.Contains(report, `"findings": null`) && !strings.Contains(report, `"findings": []`) {
		t.Errorf("expected no findings at all:\n%s", report)
	}
}

func TestSarifOutputIsWellFormedAndOmitsWaivedFindings(t *testing.T) {
	code, report := out(t, "scan", "--format", "sarif", "--waivers", "../../testdata/waivers.yaml", "../../testdata/small-plan.json")
	if code != 1 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(report, `"version": "2.1.0"`) {
		t.Error("not a SARIF 2.1.0 document")
	}
	if strings.Contains(report, "migration ticket") {
		t.Error("a waived finding's reason should not leak into SARIF (SARIF has no waiver concept)")
	}
	if !strings.Contains(report, `"ruleId": "security-group-open-sensitive-port"`) {
		t.Error("the expired-waiver finding should still be a real SARIF result")
	}
}

func TestUnreadablePlanFileExitsTwo(t *testing.T) {
	code, _ := out(t, "scan", "does-not-exist.json")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (could not read the file)", code)
	}
}

func TestNotAPlanFileExitsTwoWithAReason(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"hello": "world"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _ := out(t, "scan", bad)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestUnknownFailOnValueIsRejected(t *testing.T) {
	code, _ := out(t, "scan", "--fail-on", "severe", "../../testdata/clean-plan.json")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestBadWaiverFileIsRejected(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "waivers.yaml")
	if err := os.WriteFile(bad, []byte("waivers:\n  - rule: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _ := out(t, "scan", "--waivers", bad, "../../testdata/clean-plan.json")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (missing resource/reason/expires)", code)
	}
}

func TestNoSubcommandPrintsUsage(t *testing.T) {
	if code := run(nil); code != 2 {
		t.Fatalf("run(nil) = %d, want 2", code)
	}
	if code := run([]string{"bogus"}); code != 2 {
		t.Fatalf("run([bogus]) = %d, want 2", code)
	}
}
