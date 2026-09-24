package rules

import (
	"encoding/json"
	"strconv"

	"github.com/sriharifortitude/tfwarden/internal/planjson"
)

func init() {
	register(iamWildcardPolicy{})
}

// iamStatement is the subset of an AWS IAM policy statement this rule reads.
// Action and Resource are each either a bare string or a list of strings in
// real IAM policy JSON; RawAction/RawResource hold whichever was sent and
// asStringSet normalises it.
type iamStatement struct {
	Effect   string          `json:"Effect"`
	Action   json.RawMessage `json:"Action"`
	Resource json.RawMessage `json:"Resource"`
}

type iamDocument struct {
	Statement []iamStatement `json:"Statement"`
}

func asStringSet(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return []string{single}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	return nil
}

func containsStar(values []string) bool {
	for _, v := range values {
		if v == "*" {
			return true
		}
	}
	return false
}

// policyResourceTypes are the resource types whose `policy` attribute is a
// raw IAM policy document (as opposed to, say, an S3 bucket policy, which
// uses the same JSON shape but a different attribute name -- kept separate
// so a future rule for bucket policies is not confused with this one).
var policyResourceTypes = map[string]bool{
	"aws_iam_policy":       true,
	"aws_iam_role_policy":  true,
	"aws_iam_user_policy":  true,
	"aws_iam_group_policy": true,
}

type iamWildcardPolicy struct{}

func (iamWildcardPolicy) ID() string         { return "iam-policy-wildcard-action-resource" }
func (iamWildcardPolicy) Severity() Severity { return Critical }
func (iamWildcardPolicy) Description() string {
	return "an IAM policy has an Allow statement with Action \"*\" and Resource \"*\""
}

func (rule iamWildcardPolicy) Check(resources []planjson.Resource, _ map[string]planjson.Resource) []Finding {
	var out []Finding
	for _, r := range resources {
		if !policyResourceTypes[r.Type] {
			continue
		}
		raw, known := stringAttr(r, "policy")
		if !known {
			if !isUnknown(r, "policy") {
				continue // truly absent, not this rule's concern
			}
			out = append(out, Finding{
				RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Indeterminate,
				Message: "policy document is not known at plan time (likely built with jsonencode() over an unresolved value)",
			})
			continue
		}
		var doc iamDocument
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			// Not this rule's job to validate IAM policy syntax; a malformed
			// document is Terraform's or AWS's problem to reject at apply.
			continue
		}
		for i, stmt := range doc.Statement {
			if stmt.Effect != "Allow" {
				continue
			}
			if containsStar(asStringSet(stmt.Action)) && containsStar(asStringSet(stmt.Resource)) {
				out = append(out, Finding{
					RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Fail,
					Message:     "Statement[" + strconv.Itoa(i) + "] allows Action \"*\" on Resource \"*\"",
					Remediation: "name the specific actions and resource ARNs this role or user actually needs",
				})
			}
		}
	}
	return out
}
