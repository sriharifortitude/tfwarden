// Package rules holds the checks and the machinery that runs them.
//
// Every rule answers one question about one resource (or a resource plus
// what it can see of its neighbours) and returns a Status that is one of
// three things, never a score:
//
//	Fail          the evidence in the plan shows the problem
//	Pass          the evidence in the plan shows it is fine
//	Indeterminate the deciding attribute is not known until apply
//
// A scanner that reports Fail/Pass on data it does not actually have is
// worse than useless in a CI gate -- it trains people to ignore it. See
// docs/adr/0002-indeterminate-is-not-pass.md.
package rules

import (
	"fmt"

	"github.com/sriharifortitude/tfwarden/internal/planjson"
)

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
)

var severityOrder = map[Severity]int{Low: 0, Medium: 1, High: 2, Critical: 3}

// AtLeast reports whether s is at or above threshold.
func (s Severity) AtLeast(threshold Severity) bool {
	return severityOrder[s] >= severityOrder[threshold]
}

type Status string

const (
	Fail          Status = "fail"
	Pass          Status = "pass"
	Indeterminate Status = "indeterminate"
)

// Finding is one rule's verdict on one resource, with the evidence.
type Finding struct {
	RuleID      string
	Severity    Severity
	Resource    string // the resource address, e.g. aws_s3_bucket.data
	Status      Status
	Message     string // one sentence naming the evidence, not a category
	Remediation string
}

// Rule inspects the resources of one Terraform type and reports for each
// one it has an opinion about. A rule that has nothing to say about a
// resource (wrong type, or a required neighbour is entirely absent from
// the plan) simply does not return a Finding for it -- Pass is asserted,
// not assumed.
type Rule interface {
	ID() string
	Severity() Severity
	Description() string
	// Check runs against the whole resource set (not one resource at a
	// time) because several rules need to see a resource's neighbours
	// (an S3 bucket and its separate encryption-configuration resource).
	Check(resources []planjson.Resource, byAddress map[string]planjson.Resource) []Finding
}

var registry []Rule

func register(r Rule) {
	for _, existing := range registry {
		if existing.ID() == r.ID() {
			panic(fmt.Sprintf("rule ID %q registered twice", r.ID()))
		}
	}
	registry = append(registry, r)
}

// All returns every built-in rule, in registration order.
func All() []Rule {
	out := make([]Rule, len(registry))
	copy(out, registry)
	return out
}

// RunAll executes every rule and returns every finding, in rule order
// then resource order.
func RunAll(resources []planjson.Resource) []Finding {
	byAddress := planjson.Index(resources)
	var out []Finding
	for _, r := range All() {
		out = append(out, r.Check(resources, byAddress)...)
	}
	return out
}

// attr reads a top-level attribute, reporting whether it is known at all
// (present and not one of the unknown-until-apply keys).
func attr(r planjson.Resource, key string) (any, bool) {
	if r.Unknown[key] {
		return nil, false
	}
	v, ok := r.After[key]
	return v, ok
}

// isUnknown reports specifically that key is marked unknown-until-apply,
// as distinct from simply being absent from the plan. attr()'s single
// bool return cannot make this distinction (both cases come back false),
// and a rule that wants to say "cannot determine" rather than silently
// pass needs to.
func isUnknown(r planjson.Resource, key string) bool {
	return r.Unknown[key]
}

// boolAttr reads a boolean attribute with a default for "present, known,
// but simply absent from the plan" (Terraform omits an attribute at its
// zero value in many provider versions, and absent is not the same
// question as unknown).
func boolAttr(r planjson.Resource, key string, whenAbsent bool) (value bool, known bool) {
	v, ok := attr(r, key)
	if !ok {
		if r.Unknown[key] {
			return false, false
		}
		return whenAbsent, true
	}
	b, isBool := v.(bool)
	if !isBool {
		return false, false
	}
	return b, true
}

// stringAttr reads a string attribute.
func stringAttr(r planjson.Resource, key string) (value string, known bool) {
	v, ok := attr(r, key)
	if !ok {
		return "", false
	}
	s, isString := v.(string)
	return s, isString
}
