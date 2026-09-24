package rules

import "github.com/sriharifortitude/tfwarden/internal/planjson"

func init() {
	register(rdsPubliclyAccessible{})
	register(rdsUnencrypted{})
	register(ebsUnencrypted{})
}

type rdsPubliclyAccessible struct{}

func (rdsPubliclyAccessible) ID() string         { return "rds-publicly-accessible" }
func (rdsPubliclyAccessible) Severity() Severity { return Critical }
func (rdsPubliclyAccessible) Description() string {
	return "an RDS instance has publicly_accessible = true"
}

func (rule rdsPubliclyAccessible) Check(resources []planjson.Resource, _ map[string]planjson.Resource) []Finding {
	var out []Finding
	for _, r := range resources {
		if r.Type != "aws_db_instance" {
			continue
		}
		v, known := boolAttr(r, "publicly_accessible", false) // AWS default is false
		if !known {
			out = append(out, Finding{
				RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Indeterminate,
				Message: "publicly_accessible is not known at plan time",
			})
			continue
		}
		if v {
			out = append(out, Finding{
				RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Fail,
				Message:     "publicly_accessible = true",
				Remediation: "set publicly_accessible = false and reach the database through a VPN, bastion or VPC peering",
			})
		}
	}
	return out
}

type rdsUnencrypted struct{}

func (rdsUnencrypted) ID() string         { return "rds-storage-unencrypted" }
func (rdsUnencrypted) Severity() Severity { return High }
func (rdsUnencrypted) Description() string {
	return "an RDS instance has storage_encrypted = false or unset"
}

func (rule rdsUnencrypted) Check(resources []planjson.Resource, _ map[string]planjson.Resource) []Finding {
	var out []Finding
	for _, r := range resources {
		if r.Type != "aws_db_instance" {
			continue
		}
		// A read replica or one restored from a KMS-encrypted snapshot
		// inherits encryption and does not set storage_encrypted itself;
		// treat those as out of scope rather than guess.
		if _, isReplica := attr(r, "replicate_source_db"); isReplica {
			continue
		}
		if _, fromSnapshot := attr(r, "snapshot_identifier"); fromSnapshot {
			continue
		}
		v, known := boolAttr(r, "storage_encrypted", false) // AWS default is false
		if !known {
			out = append(out, Finding{
				RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Indeterminate,
				Message: "storage_encrypted is not known at plan time",
			})
			continue
		}
		if !v {
			out = append(out, Finding{
				RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Fail,
				Message:     "storage_encrypted = false",
				Remediation: "set storage_encrypted = true (add kms_key_id for a customer-managed key)",
			})
		}
	}
	return out
}

type ebsUnencrypted struct{}

func (ebsUnencrypted) ID() string          { return "ebs-volume-unencrypted" }
func (ebsUnencrypted) Severity() Severity  { return High }
func (ebsUnencrypted) Description() string { return "an EBS volume has encrypted = false or unset" }

func (rule ebsUnencrypted) Check(resources []planjson.Resource, _ map[string]planjson.Resource) []Finding {
	var out []Finding
	for _, r := range resources {
		if r.Type != "aws_ebs_volume" {
			continue
		}
		v, known := boolAttr(r, "encrypted", false) // AWS default is false
		if !known {
			out = append(out, Finding{
				RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Indeterminate,
				Message: "encrypted is not known at plan time",
			})
			continue
		}
		if !v {
			out = append(out, Finding{
				RuleID: rule.ID(), Severity: rule.Severity(), Resource: r.Address, Status: Fail,
				Message:     "encrypted = false",
				Remediation: "set encrypted = true",
			})
		}
	}
	return out
}
