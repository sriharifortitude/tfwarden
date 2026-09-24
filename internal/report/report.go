// Package report renders a scan's results as terminal text, JSON, or
// SARIF 2.1.0 (for GitHub code scanning and similar).
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/sriharifortitude/tfwarden/internal/rules"
	"github.com/sriharifortitude/tfwarden/internal/waiver"
)

// Row is one finding plus whatever a waiver file did to it.
type Row struct {
	rules.Finding
	WaiverOutcome waiver.Outcome
	Waiver        *waiver.Entry
}

// Result is a whole scan: every row, in a stable order (by resource then
// rule, so a re-run over the same plan produces a byte-identical report).
type Result struct {
	Rows []Row
}

func NewResult(rows []Row) Result {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Resource != rows[j].Resource {
			return rows[i].Resource < rows[j].Resource
		}
		return rows[i].RuleID < rows[j].RuleID
	})
	return Result{Rows: rows}
}

// Counts by what actually happened: a waived finding is not "clean" and
// is not "failing" -- it is its own thing, visible in every format.
type Counts struct {
	Fail          int `json:"fail"`
	Waived        int `json:"waived"`
	ExpiredWaiver int `json:"expired_waiver"`
	Indeterminate int `json:"indeterminate"`
}

func (r Result) Counts() Counts {
	var c Counts
	for _, row := range r.Rows {
		switch {
		case row.Status == rules.Indeterminate:
			c.Indeterminate++
		case row.WaiverOutcome == waiver.Expired:
			c.ExpiredWaiver++
		case row.WaiverOutcome == waiver.Waived:
			c.Waived++
		case row.Status == rules.Fail:
			c.Fail++
		}
	}
	return c
}

// Failing returns the rows that count against --fail-on: real failures
// and expired waivers, at or above the threshold severity.
func (r Result) Failing(threshold rules.Severity) []Row {
	var out []Row
	for _, row := range r.Rows {
		if row.Status != rules.Fail {
			continue
		}
		if row.WaiverOutcome == waiver.Waived {
			continue
		}
		if !row.Severity.AtLeast(threshold) {
			continue
		}
		out = append(out, row)
	}
	return out
}

func Terminal(r Result) string {
	var b strings.Builder
	for _, row := range r.Rows {
		label := statusLabel(row)
		fmt.Fprintf(&b, "%-13s %-45s %-8s %s\n", label, row.Resource, row.Severity, row.Message)
		if row.Remediation != "" && row.WaiverOutcome != waiver.Waived {
			fmt.Fprintf(&b, "              fix: %s\n", row.Remediation)
		}
		if row.Waiver != nil {
			verb := "waived"
			if row.WaiverOutcome == waiver.Expired {
				verb = "WAIVER EXPIRED"
			}
			fmt.Fprintf(&b, "              %s %s: %s\n", verb, row.Waiver.Expires, row.Waiver.Reason)
		}
	}
	c := r.Counts()
	fmt.Fprintf(&b, "\n%d findings: %d failing, %d waived, %d expired waivers, %d indeterminate\n",
		len(r.Rows), c.Fail, c.Waived, c.ExpiredWaiver, c.Indeterminate)
	return b.String()
}

func statusLabel(row Row) string {
	switch {
	case row.WaiverOutcome == waiver.Expired:
		return "EXPIRED"
	case row.WaiverOutcome == waiver.Waived:
		return "waived"
	case row.Status == rules.Indeterminate:
		return "?"
	default:
		return "FAIL"
	}
}

type jsonRow struct {
	Rule        string  `json:"rule"`
	Severity    string  `json:"severity"`
	Resource    string  `json:"resource"`
	Status      string  `json:"status"`
	Message     string  `json:"message"`
	Remediation string  `json:"remediation,omitempty"`
	Waived      bool    `json:"waived"`
	WaiverNote  *string `json:"waiver_note,omitempty"`
}

func JSON(r Result) ([]byte, error) {
	rows := make([]jsonRow, 0, len(r.Rows))
	for _, row := range r.Rows {
		jr := jsonRow{
			Rule: row.RuleID, Severity: string(row.Severity), Resource: row.Resource,
			Status: string(row.Status), Message: row.Message, Remediation: row.Remediation,
			Waived: row.WaiverOutcome == waiver.Waived,
		}
		if row.Waiver != nil {
			note := row.Waiver.Reason + " (expires " + row.Waiver.Expires + ")"
			jr.WaiverNote = &note
		}
		rows = append(rows, jr)
	}
	c := r.Counts()
	out := struct {
		Summary Counts    `json:"summary"`
		Rows    []jsonRow `json:"findings"`
	}{c, rows}
	return json.MarshalIndent(out, "", "  ")
}
