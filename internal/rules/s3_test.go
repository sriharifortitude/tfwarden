package rules

import (
	"testing"

	"github.com/sriharifortitude/tfwarden/internal/planjson"
)

func TestS3EncryptionMissing(t *testing.T) {
	good := res("aws_s3_bucket.good", "aws_s3_bucket", map[string]any{})
	bad := res("aws_s3_bucket.bad", "aws_s3_bucket", map[string]any{})
	sse := withConfig(res("aws_s3_bucket_server_side_encryption_configuration.good", "aws_s3_bucket_server_side_encryption_configuration", map[string]any{}),
		map[string]string{"bucket": "aws_s3_bucket.good"})
	resources := []planjson.Resource{good, bad, sse}

	rule := ruleByID("s3-bucket-encryption-missing")
	if got := findingsFor(rule, "aws_s3_bucket.good", resources); len(got) != 0 {
		t.Fatalf("good bucket: expected no findings, got %+v", got)
	}
	got := findingsFor(rule, "aws_s3_bucket.bad", resources)
	if len(got) != 1 || got[0].Status != Fail || got[0].Severity != High {
		t.Fatalf("bad bucket: %+v", got)
	}
}

func TestS3PublicAccessBlock(t *testing.T) {
	missing := res("aws_s3_bucket.missing", "aws_s3_bucket", map[string]any{})
	clean := res("aws_s3_bucket.clean", "aws_s3_bucket", map[string]any{})
	cleanPAB := withConfig(res("aws_s3_bucket_public_access_block.clean", "aws_s3_bucket_public_access_block",
		map[string]any{"block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true}),
		map[string]string{"bucket": "aws_s3_bucket.clean"})

	partial := res("aws_s3_bucket.partial", "aws_s3_bucket", map[string]any{})
	partialPAB := withConfig(res("aws_s3_bucket_public_access_block.partial", "aws_s3_bucket_public_access_block",
		map[string]any{"block_public_acls": false, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true}),
		map[string]string{"bucket": "aws_s3_bucket.partial"})

	unknownBucket := res("aws_s3_bucket.unknown", "aws_s3_bucket", map[string]any{})
	unknownPAB := withConfig(withUnknown(
		res("aws_s3_bucket_public_access_block.unknown", "aws_s3_bucket_public_access_block", map[string]any{"block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true}),
		"restrict_public_buckets"),
		map[string]string{"bucket": "aws_s3_bucket.unknown"})

	resources := []planjson.Resource{missing, clean, cleanPAB, partial, partialPAB, unknownBucket, unknownPAB}
	rule := ruleByID("s3-bucket-public-access-block-missing")

	if got := findingsFor(rule, "aws_s3_bucket.missing", resources); len(got) != 1 || got[0].Status != Fail {
		t.Fatalf("missing PAB: %+v", got)
	}
	if got := findingsFor(rule, "aws_s3_bucket.clean", resources); len(got) != 0 {
		t.Fatalf("all-true PAB should pass: %+v", got)
	}
	got := findingsFor(rule, "aws_s3_bucket.partial", resources)
	if len(got) != 1 || got[0].Status != Fail || got[0].Message != "aws_s3_bucket_public_access_block.partial sets block_public_acls to false" {
		t.Fatalf("partial PAB: %+v", got)
	}
	got = findingsFor(rule, "aws_s3_bucket.unknown", resources)
	if len(got) != 1 || got[0].Status != Indeterminate {
		t.Fatalf("unknown flag should be Indeterminate, not Fail or silently Pass: %+v", got)
	}
}

func TestS3VersioningDisabled(t *testing.T) {
	enabled := res("aws_s3_bucket.enabled", "aws_s3_bucket", map[string]any{})
	enabledV := withConfig(res("aws_s3_bucket_versioning.enabled", "aws_s3_bucket_versioning",
		map[string]any{"versioning_configuration": []any{map[string]any{"status": "Enabled"}}}),
		map[string]string{"bucket": "aws_s3_bucket.enabled"})

	suspended := res("aws_s3_bucket.suspended", "aws_s3_bucket", map[string]any{})
	suspendedV := withConfig(res("aws_s3_bucket_versioning.suspended", "aws_s3_bucket_versioning",
		map[string]any{"versioning_configuration": []any{map[string]any{"status": "Suspended"}}}),
		map[string]string{"bucket": "aws_s3_bucket.suspended"})

	none := res("aws_s3_bucket.none", "aws_s3_bucket", map[string]any{})

	resources := []planjson.Resource{enabled, enabledV, suspended, suspendedV, none}
	rule := ruleByID("s3-bucket-versioning-disabled")

	if got := findingsFor(rule, "aws_s3_bucket.enabled", resources); len(got) != 0 {
		t.Fatalf("Enabled should pass: %+v", got)
	}
	got := findingsFor(rule, "aws_s3_bucket.suspended", resources)
	if len(got) != 1 || got[0].Message != "aws_s3_bucket_versioning.suspended sets status = Suspended, not Enabled" {
		t.Fatalf("Suspended: %+v", got)
	}
	if got := findingsFor(rule, "aws_s3_bucket.none", resources); len(got) != 1 || got[0].Status != Fail {
		t.Fatalf("no versioning resource: %+v", got)
	}
}

func TestS3PublicACL(t *testing.T) {
	resources := []planjson.Resource{
		res("aws_s3_bucket_acl.private", "aws_s3_bucket_acl", map[string]any{"acl": "private"}),
		res("aws_s3_bucket_acl.public", "aws_s3_bucket_acl", map[string]any{"acl": "public-read"}),
		res("aws_s3_bucket_acl.publicrw", "aws_s3_bucket_acl", map[string]any{"acl": "public-read-write"}),
	}
	rule := ruleByID("s3-bucket-public-acl")
	if got := findingsFor(rule, "aws_s3_bucket_acl.private", resources); len(got) != 0 {
		t.Fatalf("private acl: %+v", got)
	}
	if got := findingsFor(rule, "aws_s3_bucket_acl.public", resources); len(got) != 1 || got[0].Message != `acl = "public-read"` {
		t.Fatalf("public-read: %+v", got)
	}
	if got := findingsFor(rule, "aws_s3_bucket_acl.publicrw", resources); len(got) != 1 {
		t.Fatalf("public-read-write: %+v", got)
	}
}
