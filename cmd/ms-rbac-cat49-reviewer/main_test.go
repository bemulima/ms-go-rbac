package main

import "testing"

func TestCAT49ReviewOwnerMarkerRejectsForeignDeployment(t *testing.T) {
	base := ownership{
		Schema: "cat49-disposable-ownership.v1", Purpose: "cat49-reviewer",
		RunID: "cat49b1717", Project: "lp-v1-cat49b1717",
		Network: "lp-v1-cat49b1717-net", AuthDatabase: "cat49_auth_business",
		RBACDatabase: "cat49_rbac_business", RBACUser: "cat49_rbac",
		PostgresHost: "127.0.0.1", PostgresPort: 5432,
	}
	if !base.valid() {
		t.Fatal("valid task marker denied")
	}
	for name, mutate := range map[string]func(*ownership){
		"shared":          func(v *ownership) { v.RBACDatabase = "lw_rbac" },
		"foreign-network": func(v *ownership) { v.Network = "foreign" },
		"foreign-run":     func(v *ownership) { v.RunID = "ment27run" },
		"wrong-purpose":   func(v *ownership) { v.Purpose = "v1-a-auth-fixture" },
		"wrong-host":      func(v *ownership) { v.PostgresHost = "platform-postgres" },
	} {
		t.Run(name, func(t *testing.T) {
			v := base
			mutate(&v)
			if v.valid() {
				t.Fatal("unsafe marker accepted")
			}
		})
	}
}

func TestCAT49RejectsUnsignedRoleGrantPreflight(t *testing.T) {
	validAuth := []byte("auth-proof-secret-with-more-than-32-bytes")
	validGrant := []byte("grant-signing-secret-with-more-than-32-bytes")
	if !grantSigningKeysReady(validAuth, validGrant) {
		t.Fatal("valid independent signing keys were denied")
	}
	for name, keys := range map[string]struct{ auth, grant []byte }{
		"missing grant":    {validAuth, nil},
		"short grant":      {validAuth, []byte("too-short")},
		"short auth":       {[]byte("too-short"), validGrant},
		"same signing key": {validAuth, validAuth},
		"oversized grant":  {validAuth, make([]byte, 4097)},
	} {
		t.Run(name, func(t *testing.T) {
			if grantSigningKeysReady(keys.auth, keys.grant) {
				t.Fatal("unsafe key pair accepted before privilege write")
			}
		})
	}
}
