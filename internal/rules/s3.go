package rules

import "github.com/sriharifortitude/tfwarden/internal/planjson"

func init() {
	register(s3EncryptionMissing{})
	register(s3PublicAccessBlockMissing{})
	register(s3VersioningDisabled{})
	register(s3PublicACL{})
}

// findReferencing returns every resource of `refType` whose `refAttr`
// (a symbolic reference in the configuration) points at target's address.
// This is the cross-resource pattern: modern AWS provider versions split
// what used to be inline S3 bucket arguments into separate resources tied
// together only by a reference, so "does this bucket have X" means
// "does some other resource of type X exist that points at this bucket".
func findReferencing(resources []planjson.Resource, refType, refAttr, targetAddr string) []planjson.Resource {
	var out []planjson.Resource
	for _, r := range resources {
		if r.Type != refType || r.Config == nil {
			continue
		}
		if ref, ok := r.Config.Reference(refAttr); ok && ref == targetAddr {
			out = append(out, r)
		}
	}
	return out
}

func nestedBlock(r planjson.Resource, key string) (map[string]any, bool) {
	v, ok := attr(r, key)
	if !ok {
		return nil, false
	}
	list, isList := v.([]any)
	if !isList || len(list) == 0 {
		return nil, false
	}
	m, isMap := list[0].(map[string]any)
	return m, isMap
}

type s3EncryptionMissing struct{}

func (s3EncryptionMissing) ID() string         { return "s3-bucket-encryption-missing" }
func (s3EncryptionMissing) Severity() Severity { return High }
func (s3EncryptionMissing) Description() string {
	return "an S3 bucket has no matching aws_s3_bucket_server_side_encryption_configuration in the plan"
}

func (rule s3EncryptionMissing) Check(resources []planjson.Resource, _ map[string]planjson.Resource) []Finding {
	var out []Finding
	for _, r := range resources {
		if r.Type != "aws_s3_bucket" {
			continue
		}
		matches := findReferencing(resources, "aws_s3_bucket_server_side_encryption_configuration", "bucket", r.Address)
		if len(matches) == 0 {
			out = append(out, Finding{
				RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Fail,
				Message:     "no aws_s3_bucket_server_side_encryption_configuration resource references this bucket, so it will be created unencrypted",
				Remediation: `add an aws_s3_bucket_server_side_encryption_configuration resource with bucket = ` + r.Address + `.id and a rule enabling SSE-S3 or SSE-KMS`,
			})
		}
	}
	return out
}

type s3PublicAccessBlockMissing struct{}

func (s3PublicAccessBlockMissing) ID() string         { return "s3-bucket-public-access-block-missing" }
func (s3PublicAccessBlockMissing) Severity() Severity { return Critical }
func (s3PublicAccessBlockMissing) Description() string {
	return "an S3 bucket has no aws_s3_bucket_public_access_block, or one that does not block everything"
}

func (rule s3PublicAccessBlockMissing) Check(resources []planjson.Resource, _ map[string]planjson.Resource) []Finding {
	var out []Finding
	for _, r := range resources {
		if r.Type != "aws_s3_bucket" {
			continue
		}
		matches := findReferencing(resources, "aws_s3_bucket_public_access_block", "bucket", r.Address)
		if len(matches) == 0 {
			out = append(out, Finding{
				RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Fail,
				Message:     "no aws_s3_bucket_public_access_block references this bucket; nothing stops it becoming public via a future ACL or policy change",
				Remediation: "add an aws_s3_bucket_public_access_block with all four flags set to true",
			})
			continue
		}
		pab := matches[0]
		flags := []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}
		var falseFlags []string
		anyUnknown := false
		for _, f := range flags {
			v, known := boolAttr(pab, f, true) // AWS default for each flag is true
			if !known {
				anyUnknown = true
				continue
			}
			if !v {
				falseFlags = append(falseFlags, f)
			}
		}
		switch {
		case len(falseFlags) > 0:
			out = append(out, Finding{
				RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Fail,
				Message:     pab.Address + " sets " + joinAnd(falseFlags) + " to false",
				Remediation: "set all four block_* / ignore_* / restrict_* flags to true unless the bucket is intentionally public",
			})
		case anyUnknown:
			out = append(out, Finding{
				RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Indeterminate,
				Message: pab.Address + " has a flag whose value depends on a resource not yet created; cannot confirm it blocks public access",
			})
		}
	}
	return out
}

type s3VersioningDisabled struct{}

func (s3VersioningDisabled) ID() string         { return "s3-bucket-versioning-disabled" }
func (s3VersioningDisabled) Severity() Severity { return Medium }
func (s3VersioningDisabled) Description() string {
	return "an S3 bucket has no versioning configuration, or versioning is not Enabled"
}

func (rule s3VersioningDisabled) Check(resources []planjson.Resource, _ map[string]planjson.Resource) []Finding {
	var out []Finding
	for _, r := range resources {
		if r.Type != "aws_s3_bucket" {
			continue
		}
		matches := findReferencing(resources, "aws_s3_bucket_versioning", "bucket", r.Address)
		if len(matches) == 0 {
			out = append(out, Finding{
				RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Fail,
				Message:     "no aws_s3_bucket_versioning references this bucket; an overwritten or deleted object cannot be recovered",
				Remediation: "add an aws_s3_bucket_versioning resource with versioning_configuration { status = \"Enabled\" }",
			})
			continue
		}
		v := matches[0]
		block, ok := nestedBlock(v, "versioning_configuration")
		if !ok {
			out = append(out, Finding{
				RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Indeterminate,
				Message: v.Address + "'s versioning_configuration is not known at plan time",
			})
			continue
		}
		status, known := stringAttr(planjson.Resource{After: block, Unknown: v.Unknown}, "status")
		if !known {
			out = append(out, Finding{
				RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Indeterminate,
				Message: v.Address + "'s versioning status is not known at plan time",
			})
		} else if status != "Enabled" {
			out = append(out, Finding{
				RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Fail,
				Message:     v.Address + " sets status = " + status + ", not Enabled",
				Remediation: "set versioning_configuration.status to \"Enabled\"",
			})
		}
	}
	return out
}

type s3PublicACL struct{}

func (s3PublicACL) ID() string         { return "s3-bucket-public-acl" }
func (s3PublicACL) Severity() Severity { return Critical }
func (s3PublicACL) Description() string {
	return "an S3 bucket ACL grants public-read or public-read-write"
}

func (rule s3PublicACL) Check(resources []planjson.Resource, _ map[string]planjson.Resource) []Finding {
	var out []Finding
	for _, r := range resources {
		if r.Type != "aws_s3_bucket_acl" {
			continue
		}
		acl, known := stringAttr(r, "acl")
		if !known {
			continue
		}
		if acl == "public-read" || acl == "public-read-write" {
			out = append(out, Finding{
				RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Fail,
				Message:     "acl = \"" + acl + "\"",
				Remediation: "use acl = \"private\" and grant access through bucket policy or IAM instead",
			})
		}
	}
	return out
}

func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	default:
		out := items[0]
		for _, s := range items[1 : len(items)-1] {
			out += ", " + s
		}
		out += " and " + items[len(items)-1]
		return out
	}
}
