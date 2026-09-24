# 2. "Not known yet" is its own status, never folded into pass or fail

Status: accepted — 2026-09-24

## Context

A plan can leave an attribute unresolved when it depends on a resource
that does not exist yet -- an RDS instance's `storage_encrypted` set from
a KMS key's ARN, an S3 bucket's public-access-block flags computed from a
module output. Terraform marks these explicitly in `after_unknown`. A
scanner has three honest options for a check that reads such an
attribute: treat unknown as compliant (a false negative that looks like
a clean report), treat it as a violation (a false positive that trains
people to distrust the tool), or say plainly that it does not know.

## Decision

Every rule's `Check` can return `Fail`, `Pass` (by simply reporting
nothing -- see the `Rule` interface doc comment), or `Indeterminate`.
`Indeterminate` is a distinct value throughout the pipeline: it has its
own bucket in `report.Counts`, it is excluded from `Failing()` so it
never flips the CI exit code, and it is omitted from SARIF results
(GitHub's code-scanning UI has no concept of "maybe" and forcing one in
would be worse than leaving it out) while still appearing in the
terminal and JSON reports as `?`.

`rules.attr` and the new `rules.isUnknown` helper exist specifically to
let a rule tell "genuinely unknown" apart from "simply absent, so the
provider's own default applies" -- these are different facts and a rule
that conflates them gets the wrong answer for both. (This distinction
was missing in an early draft: `attr()`'s single boolean return could
not separate the two cases, and the IAM wildcard-policy rule's
indeterminate path was unreachable as a result. The `internal/rules`
tests caught it before it shipped.)

## Consequences

- A `--fail-on` gate is a trustworthy pass/fail signal: it never fails
  on something the plan cannot answer, and it never quietly clears
  something the plan cannot answer either.
- The terminal and JSON reports keep indeterminate findings visible, so
  a human reviewing the plan knows exactly which resources need a second
  look once the dependency they wait on actually exists.
- A rule author has to decide, attribute by attribute, whether "absent"
  means "provider default applies" (most AWS booleans default to
  `false`) or "cannot tell" -- there is no attribute-agnostic shortcut,
  which is deliberate: guessing the same way for every attribute is how
  the false negative/positive problem above reappears one level down.
