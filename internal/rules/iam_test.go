package rules

import (
	"testing"

	"github.com/sriharifortitude/tfwarden/internal/planjson"
)

func TestIamWildcardPolicy(t *testing.T) {
	scoped := res("aws_iam_policy.scoped", "aws_iam_policy", map[string]any{
		"policy": `{"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*"}]}`,
	})
	wildcard := res("aws_iam_policy.wildcard", "aws_iam_policy", map[string]any{
		"policy": `{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}`,
	})
	// Two statements: a Deny (irrelevant) and an Allow using list-form
	// Action and string-form Resource -- both IAM shapes must be handled.
	mixed := res("aws_iam_role_policy.mixed", "aws_iam_role_policy", map[string]any{
		"policy": `{"Statement": [
			{"Effect": "Deny", "Action": "*", "Resource": "*"},
			{"Effect": "Allow", "Action": ["*"], "Resource": "*"}
		]}`,
	})
	notAPolicyResource := res("aws_iam_role.plain", "aws_iam_role", map[string]any{})
	malformed := res("aws_iam_policy.malformed", "aws_iam_policy", map[string]any{"policy": `not json`})
	unknownPolicy := withUnknown(res("aws_iam_policy.unknown", "aws_iam_policy", map[string]any{}), "policy")

	resources := []planjson.Resource{scoped, wildcard, mixed, notAPolicyResource, malformed, unknownPolicy}
	rule := ruleByID("iam-policy-wildcard-action-resource")

	if got := findingsFor(rule, "aws_iam_policy.scoped", resources); len(got) != 0 {
		t.Fatalf("scoped policy: %+v", got)
	}
	got := findingsFor(rule, "aws_iam_policy.wildcard", resources)
	if len(got) != 1 || got[0].Message != `Statement[0] allows Action "*" on Resource "*"` {
		t.Fatalf("wildcard policy: %+v", got)
	}
	got = findingsFor(rule, "aws_iam_role_policy.mixed", resources)
	if len(got) != 1 || got[0].Message != `Statement[1] allows Action "*" on Resource "*"` {
		t.Fatalf("mixed statements (Deny ignored, index 1 flagged): %+v", got)
	}
	if got := findingsFor(rule, "aws_iam_role.plain", resources); len(got) != 0 {
		t.Fatalf("a resource type this rule does not cover: %+v", got)
	}
	if got := findingsFor(rule, "aws_iam_policy.malformed", resources); len(got) != 0 {
		t.Fatalf("malformed policy JSON is not this rule's job to flag: %+v", got)
	}
	got = findingsFor(rule, "aws_iam_policy.unknown", resources)
	if len(got) != 1 || got[0].Status != Indeterminate {
		t.Fatalf("policy built from an unresolved jsonencode(): %+v", got)
	}
}
