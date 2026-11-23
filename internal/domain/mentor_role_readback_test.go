package domain

import "testing"

func TestMentorRoleReadbackResultShape(t *testing.T) {
	approve := mentorTestCommand(MentorRoleDecisionApprove, 2)
	suspend := mentorTestCommand(MentorRoleDecisionSuspend, 3)
	for _, tc := range []struct {
		name    string
		command MentorRoleCommand
		result  MentorRoleReadbackResult
		valid   bool
	}{
		{"active approval", approve, MentorRoleReadbackResult{true, true}, true},
		{"inactive suspension", suspend, MentorRoleReadbackResult{true, false}, true},
		{"unknown approval", approve, MentorRoleReadbackResult{}, true},
		{"unknown suspension", suspend, MentorRoleReadbackResult{}, true},
		{"inactive approval", approve, MentorRoleReadbackResult{true, false}, false},
		{"active suspension", suspend, MentorRoleReadbackResult{true, true}, false},
		{"unconfirmed active", approve, MentorRoleReadbackResult{false, true}, false},
		{"invalid command", MentorRoleCommand{}, MentorRoleReadbackResult{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidMentorRoleReadbackResult(tc.command, tc.result); got != tc.valid {
				t.Fatalf("valid=%v, want %v", got, tc.valid)
			}
		})
	}
}
