// Command tfwarden scans a Terraform plan for security misconfigurations.
//
//	terraform plan -out=plan.tfplan
//	terraform show -json plan.tfplan > plan.json
//	tfwarden scan plan.json
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/sriharifortitude/tfwarden/internal/planjson"
	"github.com/sriharifortitude/tfwarden/internal/report"
	"github.com/sriharifortitude/tfwarden/internal/rules"
	"github.com/sriharifortitude/tfwarden/internal/waiver"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 || args[0] != "scan" {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	fs := newFlagSet()
	if err := fs.Parse(args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "scan: expected exactly one plan JSON file")
		return 2
	}

	planPath := fs.Arg(0)
	planData, err := os.ReadFile(planPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading %s: %s\n", planPath, err)
		return 2
	}
	plan, err := planjson.Parse(planData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", planPath, err)
		return 2
	}

	var w waiver.File
	if fs.waivers != "" {
		data, err := os.ReadFile(fs.waivers)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading %s: %s\n", fs.waivers, err)
			return 2
		}
		parsed, err := waiver.Parse(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n", fs.waivers, err)
			return 2
		}
		w = *parsed
	}

	threshold, err := parseSeverity(fs.failOn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	findings := rules.RunAll(plan.Resources())
	rows := make([]report.Row, 0, len(findings))
	today := time.Now()
	for _, f := range findings {
		outcome, entry := w.Apply(f, today)
		rows = append(rows, report.Row{Finding: f, WaiverOutcome: outcome, Waiver: entry})
	}
	result := report.NewResult(rows)

	out, err := render(result, fs.format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rendering %s report: %s\n", fs.format, err)
		return 2
	}
	if err := write(out, fs.output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if fs.output != "" && fs.format != "terminal" {
		fmt.Print(report.Terminal(result))
	}

	if len(result.Failing(threshold)) > 0 {
		return 1
	}
	return 0
}

func render(r report.Result, format string) (string, error) {
	switch format {
	case "terminal", "":
		return report.Terminal(r), nil
	case "json":
		b, err := report.JSON(r)
		return string(b) + "\n", err
	case "sarif":
		b, err := report.SARIF(r)
		return string(b) + "\n", err
	default:
		return "", fmt.Errorf("unknown format %q: expected terminal, json or sarif", format)
	}
}

func write(text, path string) error {
	if path == "" {
		fmt.Print(text)
		return nil
	}
	return os.WriteFile(path, []byte(text), 0o644)
}

func parseSeverity(s string) (rules.Severity, error) {
	switch s {
	case "low", "":
		return rules.Low, nil
	case "medium":
		return rules.Medium, nil
	case "high":
		return rules.High, nil
	case "critical":
		return rules.Critical, nil
	default:
		return "", fmt.Errorf("--fail-on: expected low, medium, high or critical, got %q", s)
	}
}

const usage = `usage: tfwarden scan [--format terminal|json|sarif] [--output FILE] [--fail-on low|medium|high|critical] [--waivers FILE] <plan.json>`
