package usecase

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain/repository"
)

type cat49GrantSpy struct{ calls int }

func (s *cat49GrantSpy) GrantCAT49Reviewer(_ context.Context, _ repository.CAT49ReviewerGrantIntent) (repository.CAT49ReviewerGrantReceipt, error) {
	s.calls++
	return repository.CAT49ReviewerGrantReceipt{Role: "moderator"}, nil
}
func TestCAT49VerifiedAuthReceiptAndOneRoleIntent(t *testing.T) {
	key := []byte(strings.Repeat("K", 48))
	p := repository.CAT49RegistrationReceipt{
		Schema: "cat49-disposable-reviewer-registration.v1",
		RunID:  "cat49b1717", RequestID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		PrincipalID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", AuthDatabase: "cat49_auth_business",
		IntentDigest: "sha256:" + strings.Repeat("a", 64),
	}
	body, _ := json.Marshal(cat49RegistrationFields(p))
	p.ReceiptDigest = cat49Hash(body)
	signed, _ := json.Marshal(cat49RegistrationSignedFields(p))
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(signed)
	p.Signature = "sha256:" + fmtHex(m.Sum(nil))
	raw, _ := json.Marshal(p)
	got, err := VerifyCAT49Registration(raw, key, p.RunID, p.AuthDatabase)
	if err != nil || got.PrincipalID != p.PrincipalID {
		t.Fatalf("valid receipt rejected: %v", err)
	}
	for name, alter := range map[string]func(*repository.CAT49RegistrationReceipt){
		"foreign run":         func(v *repository.CAT49RegistrationReceipt) { v.RunID = "foreignrun" },
		"other principal":     func(v *repository.CAT49RegistrationReceipt) { v.PrincipalID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc" },
		"wrong role evidence": func(v *repository.CAT49RegistrationReceipt) { v.Schema = "generic-signup.v1" },
	} {
		t.Run(name, func(t *testing.T) {
			v := p
			alter(&v)
			raw, _ := json.Marshal(v)
			if _, err := VerifyCAT49Registration(raw, key, p.RunID, p.AuthDatabase); err == nil {
				t.Fatal("tampered receipt accepted")
			}
		})
	}
	duplicates := append([]byte(nil), raw[:len(raw)-1]...)
	duplicates = append(duplicates, []byte(",\"run_id\":\"cat49b1717\"}")...)
	if _, err := VerifyCAT49Registration(duplicates, key, p.RunID, p.AuthDatabase); err == nil {
		t.Fatal("duplicate key accepted")
	}
	spy := &cat49GrantSpy{}
	bad := repository.CAT49ReviewerGrantIntent{RunID: p.RunID, PrincipalID: p.PrincipalID, RequestID: p.RequestID, AuthReceiptDigest: "", Operator: "cat49"}
	if _, err := GrantCAT49Reviewer(context.Background(), spy, bad); err == nil || spy.calls != 0 {
		t.Fatal("unverified grant reached store")
	}
}
func fmtHex(src []byte) string {
	const symbols = "0123456789abcdef"
	dst := make([]byte, len(src)*2)
	for i, b := range src {
		dst[i*2] = symbols[b>>4]
		dst[i*2+1] = symbols[b&15]
	}
	return string(dst)
}
