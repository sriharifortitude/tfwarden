// Package waiver applies accepted-risk suppressions to findings.
//
// A waiver names a rule and a resource address, not a whole rule or a
// whole run: silencing "s3-bucket-encryption-missing" everywhere because
// one legacy bucket is exempt would also silence it for the next bucket
// someone adds. A waiver without an expiry is refused at load time --
// accepted risk that is never revisited is not a decision, it is
// forgetting on purpose.
package waiver

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sriharifortitude/tfwarden/internal/rules"
)

type Entry struct {
	Rule     string `yaml:"rule"`
	Resource string `yaml:"resource"`
	Reason   string `yaml:"reason"`
	Expires  string `yaml:"expires"` // YYYY-MM-DD
}

type File struct {
	Waivers []Entry `yaml:"waivers"`
}

func Parse(data []byte) (*File, error) {
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("not valid YAML: %w", err)
	}
	for i, w := range f.Waivers {
		at := fmt.Sprintf("waivers[%d]", i)
		if w.Rule == "" {
			return nil, fmt.Errorf("%s.rule: required", at)
		}
		if w.Resource == "" {
			return nil, fmt.Errorf("%s.resource: required (the exact resource address, not a wildcard)", at)
		}
		if w.Reason == "" {
			return nil, fmt.Errorf("%s.reason: required -- say why this is accepted risk", at)
		}
		if w.Expires == "" {
			return nil, fmt.Errorf("%s.expires: required (YYYY-MM-DD) -- a waiver without a review date is not a decision", at)
		}
		if _, err := time.Parse("2006-01-02", w.Expires); err != nil {
			return nil, fmt.Errorf("%s.expires: %q is not YYYY-MM-DD", at, w.Expires)
		}
	}
	return &f, nil
}

// Outcome of applying waivers to one finding.
type Outcome int

const (
	NotWaived Outcome = iota
	Waived
	Expired
)

// Apply reports whether a finding is covered by a waiver, and whether that
// waiver has expired. An expired waiver does not suppress the finding --
// it is why the finding is failing again.
func (f *File) Apply(finding rules.Finding, today time.Time) (Outcome, *Entry) {
	for i := range f.Waivers {
		w := &f.Waivers[i]
		if w.Rule != finding.RuleID || w.Resource != finding.Resource {
			continue
		}
		expires, _ := time.Parse("2006-01-02", w.Expires) // validated in Parse
		if today.After(expires) {
			return Expired, w
		}
		return Waived, w
	}
	return NotWaived, nil
}
