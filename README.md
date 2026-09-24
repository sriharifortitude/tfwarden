# tfwarden

[![CI](https://github.com/sriharifortitude/tfwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/tfwarden/actions/workflows/ci.yml)

A Terraform plan scanner: ten checks for the AWS misconfigurations that
show up in almost every real incident report -- public S3 buckets,
security groups open to the internet, unencrypted storage, IAM policies
that grant everything. Reads `terraform show -json`, not the `.tf`
source, so it sees exactly what will be created -- every variable
resolved, every module expanded -- rather than re-implementing
Terraform's own evaluator badly. See
[ADR 1](docs/adr/0001-plan-json-not-hcl.md).

```
$ terraform plan -out=p && terraform show -json p > plan.json
$ tfwarden scan --waivers waivers.yaml plan.json

FAIL          aws_s3_bucket.legacy                          HIGH     no aws_s3_bucket_server_side_encryption_configuration resource references this bucket, so it will be created unencrypted
              fix: add an aws_s3_bucket_server_side_encryption_configuration resource with bucket = aws_s3_bucket.legacy.id and a rule enabling SSE-S3 or SSE-KMS
FAIL          aws_s3_bucket.legacy                          CRITICAL no aws_s3_bucket_public_access_block references this bucket; nothing stops it becoming public via a future ACL or policy change
              fix: add an aws_s3_bucket_public_access_block with all four flags set to true
waived        aws_s3_bucket.legacy                          MEDIUM   no aws_s3_bucket_versioning references this bucket; an overwritten or deleted object cannot be recovered
              waived 2030-01-01: pre-dates the versioning requirement, migration ticket JIRA-42
EXPIRED       aws_security_group.web                        CRITICAL ingress from 0.0.0.0/0 allows SSH (port 22)
              fix: restrict cidr_blocks to known ranges, or front this with a bastion / VPN
              WAIVER EXPIRED 2025-01-01: was meant to be temporary while the bastion was being set up

4 findings: 2 failing, 1 waived, 1 expired waivers, 0 indeterminate
$ echo $?
1
```

(Real output from `testdata/small-plan.json` and `testdata/waivers.yaml`
in this repository -- run it yourself with the command above.)

## The checks

| rule | severity | what it catches |
| --- | --- | --- |
| `s3-bucket-encryption-missing` | High | a bucket with no `aws_s3_bucket_server_side_encryption_configuration` pointing at it |
| `s3-bucket-public-access-block-missing` | Critical | missing, or one that leaves a `block_*`/`ignore_*`/`restrict_*` flag off |
| `s3-bucket-versioning-disabled` | Medium | no versioning resource, or `status` not `Enabled` |
| `s3-bucket-public-acl` | Critical | `acl = "public-read"` or `"public-read-write"` |
| `security-group-open-sensitive-port` | Critical | `0.0.0.0/0` ingress reaching SSH, RDP, MySQL, PostgreSQL, Redis or MongoDB |
| `security-group-open-all-ports` | Critical | `0.0.0.0/0` ingress spanning every port (a `0-65535` range, or `protocol = "-1"`) |
| `rds-publicly-accessible` | Critical | `publicly_accessible = true` |
| `rds-storage-unencrypted` | High | `storage_encrypted` false or unset (read replicas and snapshot restores are skipped -- they inherit encryption) |
| `ebs-volume-unencrypted` | High | `encrypted` false or unset |
| `iam-policy-wildcard-action-resource` | Critical | an `Allow` statement with `Action "*"` on `Resource "*"` |

Every finding names the exact evidence (`block_public_acls to false`,
`Statement[1] allows Action "*"`), not a category, and carries a one-line
fix. `docs/adr/` explains what each check does and does not attempt.

## What "indeterminate" means

A plan can leave an attribute unresolved -- an RDS instance's encryption
flag set from a KMS key that does not exist yet. tfwarden never guesses
in either direction for that: the finding is `?` / `indeterminate`, kept
out of the pass/fail count and out of SARIF (which has no concept of
"maybe"), and still visible in the terminal and JSON reports so nothing
silently drops off the list. [ADR 2](docs/adr/0002-indeterminate-is-not-pass.md)
is the full reasoning; it also records a real bug this distinction
caught in its own test suite before shipping.

## Waivers

Accepted risk is named per rule and per resource, with a reason and an
expiry date -- all four required (`internal/waiver`). A waiver that has
expired stops suppressing its finding and is shown as `WAIVER EXPIRED`,
still failing the gate, which is the difference between accepted risk
and forgetting about it:

```yaml
waivers:
  - rule: s3-bucket-versioning-disabled
    resource: aws_s3_bucket.legacy
    reason: pre-dates the versioning requirement, migration ticket JIRA-42
    expires: "2030-01-01"
```

## Output formats and exit codes

`--format terminal|json|sarif`, `--output FILE`, `--fail-on
low|medium|high|critical` (default `low`: anything Fail fails the run).
SARIF 2.1.0 is for GitHub code scanning; every declared rule appears in
the SARIF `rules` array even when it found nothing, so severities are
visible before a first violation ever happens.

| exit code | meaning |
| --- | --- |
| 0 | nothing failing at or above `--fail-on` |
| 1 | at least one finding does (an expired waiver counts) |
| 2 | the plan or waivers file could not be read or parsed |

## Running it

    go install github.com/sriharifortitude/tfwarden/cmd/tfwarden@v0.1.0
    tfwarden scan plan.json

Or the image: `docker run --rm -v "$PWD:/w" ghcr.io/sriharifortitude/tfwarden:0.1 scan /w/plan.json`.

## Checks

    go build ./... && go vet ./... && staticcheck ./...
    go test ./... -cover

36 tests: `internal/planjson` parses real plan-JSON shapes including
module nesting and cross-resource references; `internal/rules` builds
resources directly in Go (precise, no JSON-schema fragility) for every
rule and every edge case -- unknown-vs-absent, mixed IAM policy shapes,
protocol `-1`; `internal/waiver` and `internal/report` are hand-verified
against exact text; `cmd/tfwarden` runs the whole pipeline against real
files on disk and checks exit codes. No external services -- a static
analyzer over a JSON file needs none, which was itself worth choosing on
a machine where Docker had gone down mid-project.

## What it deliberately does not do

- **AWS only**, and ten checks, not two hundred. Breadth is what Checkov
  and Terrascan already do well; this is the depth-over-coverage bet the
  rest of the portfolio makes too.
- **The classic inline `aws_security_group` `ingress` block only.** The
  newer split-resource model (`aws_vpc_security_group_ingress_rule`, one
  resource per rule) is not read. Both are common in the wild; this is a
  real gap, not an oversight, and the next rule to add.
- **No account-level defaults.** `aws_ebs_encryption_by_default` can make
  an EBS volume encrypted even with `encrypted` unset in its own
  resource; tfwarden does not chase that cross-account setting and will
  flag the volume anyway. State it explicitly per-resource to clear it.
- **No state file, no drift detection.** A plan is what will change;
  what is already running and never touched again by Terraform is out of
  scope.
- **No remediation applied.** It tells you what is wrong and one way to
  fix it; it edits nothing.

## Licence

MIT.
