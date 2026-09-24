# 1. Scan `terraform show -json`, not the `.tf` source

Status: accepted — 2026-09-24

## Context

A Terraform security scanner can read either the raw HCL source files or
the structured JSON that `terraform show -json <plan>` produces. Every
established tool in this space (Checkov, tfsec, Terrascan) supports HCL
scanning because it needs no `terraform plan` step and can run on a
single file with no state. But HCL scanning means re-implementing a
subset of Terraform's own evaluator: variables, `locals`, module calls
with their own variables, `count`/`for_each` expansion, and functions
like `jsonencode()`. Getting that subset wrong produces exactly the
failure mode a security tool cannot afford -- a resource that silently
never gets checked because its value came from an expression the scanner
did not evaluate.

## Decision

tfwarden reads the plan JSON (`terraform show -json`), not `.tf` files.
By the time Terraform has produced that document, every variable is
substituted, every module call is expanded, every `count`/`for_each`
instance is a separate resource change with its own address, and
`jsonencode()` calls have already become the JSON string they represent.
tfwarden's job shrinks to reading a schema, not evaluating a language.

Symbolic references between resources (which bucket does this encryption
config belong to?) do not survive into the resolved values, so the
`configuration` section of the same document -- which keeps expression
references -- is read alongside `resource_changes` for the handful of
rules that need to know one resource points at another
(`planjson.ResourceConfig.Reference`).

## Consequences

- The workflow this asks of a user is one line longer than "point a
  scanner at a directory": `terraform plan -out=p && terraform show
  -json p > p.json`. That is the same plan step every real deployment
  already runs, so in a CI pipeline it costs nothing extra.
- A resource whose value depends on something not yet created shows up
  in the plan as explicitly unknown (`after_unknown`), which tfwarden
  can and does distinguish from "known to be compliant" -- see ADR 2.
  An HCL-only scanner has no equivalent signal; it either evaluates
  wrongly or refuses to evaluate at all.
- What tfwarden cannot do: comment on code that will never produce a
  plan (a module nobody calls, a resource behind a variable that is
  always false in this environment), or run as a pre-commit hook with
  no cloud credentials and no state. Both are real HCL-scanner
  strengths and a real limitation here, stated in the README.
- Terraform's own plan JSON schema is versioned (`format_version`); the
  parser checks it is `1.x` and refuses anything else with that
  reason, rather than silently misreading a future incompatible schema.
