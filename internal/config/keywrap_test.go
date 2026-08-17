package config

import "testing"

func TestAWSKMSWrapperTOML(t *testing.T) {
	path := writeConfig(t, "kms.toml", `schema_version = 1
[encryption]
primary_wrapper = "aws-primary"

[[encryption.wrappers]]
name = "aws-primary"
kind = "aws-kms"
[encryption.wrappers.aws_kms]
key_arn = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"
region = "us-east-1"
`)
	result, err := Load(Options{Path: path, LookupEnv: emptyEnv})
	if err != nil {
		t.Fatal(err)
	}
	if result.Config.Encryption.PrimaryWrapper != "aws-primary" || len(result.Config.Encryption.Wrappers) != 1 {
		t.Fatalf("encryption wrappers = %#v", result.Config.Encryption)
	}
	aws := result.Config.Encryption.Wrappers[0].AWSKMS
	if aws == nil || aws.Region != "us-east-1" {
		t.Fatalf("AWS KMS config = %#v", aws)
	}
}

func TestKeyWrapperTOMLFailsClosed(t *testing.T) {
	for _, body := range []string{
		"[encryption]\nprimary_wrapper='missing'\n",
		"[encryption]\nprimary_wrapper='one'\n[[encryption.wrappers]]\nname='one'\nkind='aws-kms'\n",
		"[encryption]\nprimary_wrapper='one'\n[[encryption.wrappers]]\nname='one'\nkind='shell'\n",
	} {
		path := writeConfig(t, "invalid-kms.toml", "schema_version=1\n"+body)
		if _, err := Load(Options{Path: path, LookupEnv: emptyEnv}); err == nil {
			t.Fatalf("invalid wrapper TOML accepted: %s", body)
		}
	}
}
