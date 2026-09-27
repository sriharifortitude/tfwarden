# Source for plan.json (regenerate with ./generate.sh). Real Terraform output
# covering the two address shapes v0.1.0 could not match configuration to:
# resources inside a module, and resources with count / for_each.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.0, < 7.0" }
  }
}

provider "aws" {
  region                      = "eu-central-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

# Fully configured, but created with count: addresses are aws_s3_bucket.counted[0] and [1].
resource "aws_s3_bucket" "counted" {
  count  = 2
  bucket = "tfwarden-counted-${count.index}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "counted" {
  count  = 2
  bucket = aws_s3_bucket.counted[count.index].id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "counted" {
  count                   = 2
  bucket                  = aws_s3_bucket.counted[count.index].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "counted" {
  count  = 2
  bucket = aws_s3_bucket.counted[count.index].id
  versioning_configuration { status = "Enabled" }
}

# The same module twice, so two buckets share the module-relative address
# aws_s3_bucket.this. One instance is fully configured, one is not.
module "good" {
  source = "./modules/store"
  name   = "tfwarden-good"
  harden = true
}

module "bad" {
  source = "./modules/store"
  name   = "tfwarden-bad"
  harden = false
}
