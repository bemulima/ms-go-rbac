package domain

import (
	"strings"
	"testing"
)

func mentorRoleStoreTestProof() MentorRoleProof {
	return MentorRoleProof{
		Command: mentorTestCommand(MentorRoleDecisionApprove, 2),
		JWTID:   "00000000-0000-4000-8000-000000000e01", ProofDigest: strings.Repeat("a1", 32),
		IssuedAt: 2000000000, ExpiresAt: 2000000030,
	}
}

func TestMentorRoleProofShapeAcceptsBoundedValuesWithoutClaimingFreshness(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*MentorRoleProof)
	}{
		{"approve", func(*MentorRoleProof) {}},
		{"suspend pending", func(p *MentorRoleProof) { p.Command = mentorTestCommand(MentorRoleDecisionSuspend, 3) }},
		{"suspend approved", func(p *MentorRoleProof) { p.Command = mentorTestCommand(MentorRoleDecisionSuspend, 4) }},
		{"maximum timestamp", func(p *MentorRoleProof) {
			p.IssuedAt = MentorRoleProofMaxTimestamp - 30
			p.ExpiresAt = MentorRoleProofMaxTimestamp
		}},
		{"historical value is shape only", func(p *MentorRoleProof) { p.IssuedAt = 1; p.ExpiresAt = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := mentorRoleStoreTestProof()
			tc.edit(&proof)
			if !ValidMentorRoleProofShape(proof) {
				t.Fatal("valid value shape rejected")
			}
		})
	}
}

func TestMentorRoleProofShapeRejectsMalformedMetadata(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*MentorRoleProof)
	}{
		{"invalid command", func(p *MentorRoleProof) { p.Command.Role = "admin" }},
		{"empty JTI", func(p *MentorRoleProof) { p.JWTID = "" }},
		{"nil JTI", func(p *MentorRoleProof) { p.JWTID = "00000000-0000-0000-0000-000000000000" }},
		{"uppercase JTI", func(p *MentorRoleProof) { p.JWTID = strings.ToUpper(p.JWTID) }},
		{"empty digest", func(p *MentorRoleProof) { p.ProofDigest = "" }},
		{"short digest", func(p *MentorRoleProof) { p.ProofDigest = p.ProofDigest[1:] }},
		{"uppercase digest", func(p *MentorRoleProof) { p.ProofDigest = strings.ToUpper(p.ProofDigest) }},
		{"invalid digest", func(p *MentorRoleProof) { p.ProofDigest = strings.Repeat("g", 64) }},
		{"zero iat", func(p *MentorRoleProof) { p.IssuedAt = 0 }},
		{"negative iat", func(p *MentorRoleProof) { p.IssuedAt = -1 }},
		{"zero exp", func(p *MentorRoleProof) { p.ExpiresAt = 0 }},
		{"negative exp", func(p *MentorRoleProof) { p.ExpiresAt = -1 }},
		{"exp equal iat", func(p *MentorRoleProof) { p.ExpiresAt = p.IssuedAt }},
		{"exp before iat", func(p *MentorRoleProof) { p.ExpiresAt = p.IssuedAt - 1 }},
		{"long TTL", func(p *MentorRoleProof) { p.ExpiresAt = p.IssuedAt + 31 }},
		{"unsafe iat", func(p *MentorRoleProof) { p.IssuedAt = MentorRoleProofMaxTimestamp + 1 }},
		{"unsafe exp", func(p *MentorRoleProof) { p.ExpiresAt = MentorRoleProofMaxTimestamp + 1 }},
		{"signed overflow boundary", func(p *MentorRoleProof) { p.IssuedAt = -1 << 63; p.ExpiresAt = 1<<63 - 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := mentorRoleStoreTestProof()
			tc.edit(&proof)
			if ValidMentorRoleProofShape(proof) {
				t.Fatal("malformed value shape accepted")
			}
		})
	}
}
