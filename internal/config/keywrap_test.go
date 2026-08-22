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

func TestOpenBaoWrapperTOML(t *testing.T) {
	path := writeConfig(t, "openbao.toml", `schema_version = 1
[encryption]
primary_wrapper = "bao-primary"
[[encryption.wrappers]]
name = "bao-primary"
kind = "openbao-transit"
[encryption.wrappers.openbao]
address = "https://openbao.example"
mount = "transit"
key_name = "agent-vault"
auth_mount = "cert"
role = "agent-vault"
`)
	result, err := Load(Options{Path: path, LookupEnv: emptyEnv})
	if err != nil {
		t.Fatal(err)
	}
	bao := result.Config.Encryption.Wrappers[0].OpenBao
	if bao == nil || bao.KeyName != "agent-vault" || bao.Role != "agent-vault" {
		t.Fatalf("OpenBao config = %#v", bao)
	}
}

func TestAgeRecoveryTOMLHasNoPrivateIdentityField(t *testing.T) {
	path := writeConfig(t, "age.toml", `schema_version = 1
[encryption]
primary_wrapper = "primary"
[[encryption.wrappers]]
name = "primary"
kind = "aws-kms"
[encryption.wrappers.aws_kms]
key_arn = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"
region = "us-east-1"
[[encryption.wrappers]]
name = "recovery"
kind = "age-x25519"
[encryption.wrappers.age]
recipient = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
`)
	result, err := Load(Options{Path: path, LookupEnv: emptyEnv})
	if err != nil {
		t.Fatal(err)
	}
	if result.Config.Encryption.Wrappers[1].Age == nil {
		t.Fatal("age recipient was not loaded")
	}
	privatePath := writeConfig(t, "age-private.toml", `schema_version = 1
[encryption]
primary_wrapper = "recovery"
[[encryption.wrappers]]
name = "recovery"
kind = "age-x25519"
[encryption.wrappers.age]
recipient = "age1public"
identity = "AGE-SECRET-KEY-DO-NOT-LOAD"
`)
	if _, err := Load(Options{Path: privatePath, LookupEnv: emptyEnv}); err == nil {
		t.Fatal("private age identity was accepted in runtime TOML")
	}
}
