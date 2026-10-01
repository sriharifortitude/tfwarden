#!/usr/bin/env bash
# Regenerates plan.json from main.tf with no AWS account (credential checks
# skipped, nothing refreshed; no data source here calls the AWS API).
set -euo pipefail
cd "$(dirname "$0")"
trap 'rm -rf .terraform .terraform.lock.hcl tfplan' EXIT
terraform init -input=false -backend=false > /dev/null
terraform plan -input=false -refresh=false -lock=false -out=tfplan > /dev/null
terraform show -json tfplan > plan.json
