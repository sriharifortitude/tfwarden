package rules

import (
	"testing"

	"github.com/sriharifortitude/tfwarden/internal/planjson"
)

func TestRdsPubliclyAccessible(t *testing.T) {
	private := res("aws_db_instance.private", "aws_db_instance", map[string]any{"publicly_accessible": false})
	public := res("aws_db_instance.public", "aws_db_instance", map[string]any{"publicly_accessible": true})
	absent := res("aws_db_instance.absent", "aws_db_instance", map[string]any{}) // AWS default is false
	unknown := withUnknown(res("aws_db_instance.unknown", "aws_db_instance", map[string]any{}), "publicly_accessible")

	resources := []planjson.Resource{private, public, absent, unknown}
	rule := ruleByID("rds-publicly-accessible")

	if got := findingsFor(rule, "aws_db_instance.private", resources); len(got) != 0 {
		t.Fatalf("private: %+v", got)
	}
	if got := findingsFor(rule, "aws_db_instance.public", resources); len(got) != 1 || got[0].Status != Fail {
		t.Fatalf("public: %+v", got)
	}
	if got := findingsFor(rule, "aws_db_instance.absent", resources); len(got) != 0 {
		t.Fatalf("absent (default false): %+v", got)
	}
	if got := findingsFor(rule, "aws_db_instance.unknown", resources); len(got) != 1 || got[0].Status != Indeterminate {
		t.Fatalf("unknown: %+v", got)
	}
}

func TestRdsUnencryptedSkipsReplicasAndSnapshotRestores(t *testing.T) {
	plain := res("aws_db_instance.plain", "aws_db_instance", map[string]any{"storage_encrypted": false})
	replica := res("aws_db_instance.replica", "aws_db_instance", map[string]any{"replicate_source_db": "source-id"})
	fromSnapshot := res("aws_db_instance.restored", "aws_db_instance", map[string]any{"snapshot_identifier": "snap-1"})
	encrypted := res("aws_db_instance.encrypted", "aws_db_instance", map[string]any{"storage_encrypted": true})

	resources := []planjson.Resource{plain, replica, fromSnapshot, encrypted}
	rule := ruleByID("rds-storage-unencrypted")

	if got := findingsFor(rule, "aws_db_instance.plain", resources); len(got) != 1 {
		t.Fatalf("plain unencrypted: %+v", got)
	}
	if got := findingsFor(rule, "aws_db_instance.replica", resources); len(got) != 0 {
		t.Fatalf("a replica inherits encryption and should be skipped: %+v", got)
	}
	if got := findingsFor(rule, "aws_db_instance.restored", resources); len(got) != 0 {
		t.Fatalf("restored from snapshot should be skipped: %+v", got)
	}
	if got := findingsFor(rule, "aws_db_instance.encrypted", resources); len(got) != 0 {
		t.Fatalf("encrypted: %+v", got)
	}
}

func TestEbsVolumeUnencrypted(t *testing.T) {
	plain := res("aws_ebs_volume.plain", "aws_ebs_volume", map[string]any{})
	encrypted := res("aws_ebs_volume.encrypted", "aws_ebs_volume", map[string]any{"encrypted": true})
	unknown := withUnknown(res("aws_ebs_volume.unknown", "aws_ebs_volume", map[string]any{}), "encrypted")

	resources := []planjson.Resource{plain, encrypted, unknown}
	rule := ruleByID("ebs-volume-unencrypted")

	if got := findingsFor(rule, "aws_ebs_volume.plain", resources); len(got) != 1 || got[0].Status != Fail {
		t.Fatalf("plain (default false): %+v", got)
	}
	if got := findingsFor(rule, "aws_ebs_volume.encrypted", resources); len(got) != 0 {
		t.Fatalf("encrypted: %+v", got)
	}
	got := findingsFor(rule, "aws_ebs_volume.unknown", resources)
	if len(got) != 1 || got[0].Status != Indeterminate {
		t.Fatalf("unknown (e.g. depends on a KMS key not yet created): %+v", got)
	}
}
