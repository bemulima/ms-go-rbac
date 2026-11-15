package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
)

const (
	mentorTestAdmin          = "00000000-0000-4000-8000-000000000a01"
	mentorTestUser           = "00000000-0000-4000-8000-000000000b01"
	mentorTestApplication    = "00000000-0000-4000-8000-000000000c01"
	mentorTestApproveRequest = "00000000-0000-4000-8000-000000000d01"
	mentorTestSuspendRequest = "00000000-0000-4000-8000-000000000d02"
)

func mentorTestCommand(decision string, revision uint64) MentorRoleCommand {
	request := mentorTestApproveRequest
	if decision == MentorRoleDecisionSuspend {
		request = mentorTestSuspendRequest
	}
	command := MentorRoleCommand{
		Issuer: MentorRoleProofIssuer, AdminID: mentorTestAdmin,
		TargetUserID: mentorTestUser, ApplicationID: mentorTestApplication,
		ApplicationRevision: revision, Decision: decision, RequestID: request,
		Role: MentorRole, Service: MentorRoleService,
	}
	return mentorTestDigest(command)
}

func mentorTestDigest(command MentorRoleCommand) MentorRoleCommand {
	digest := sha256.Sum256([]byte(command.Decision + "|" + command.AdminID + "|" + command.ApplicationID + "|" + command.RequestID + "|" + strconv.FormatUint(command.ApplicationRevision-1, 10)))
	command.DecisionDigest = hex.EncodeToString(digest[:])
	return command
}

func mentorTestSnapshot(plan MentorRolePlan) MentorRoleSnapshot {
	application, target := plan.Current, plan.Current
	return MentorRoleSnapshot{ApplicationFence: &application, TargetFence: &target}
}

func TestMentorRolePlanApprovalThenHistoricalReplayAfterSuspension(t *testing.T) {
	approve := mentorTestCommand(MentorRoleDecisionApprove, 2)
	first, err := PlanMentorRoleCommand(approve, MentorRoleSnapshot{})
	if err != nil || !first.Write || first.Replay || !first.Current.Active || first.Current.Suspended || first.Receipt.Command != approve {
		t.Fatalf("approval must plan one scoped grant and immutable receipt: %v", err)
	}
	snapshot := mentorTestSnapshot(first)
	snapshot.Receipt = &first.Receipt
	replay, err := PlanMentorRoleCommand(approve, snapshot)
	if err != nil || replay.Write || !replay.Replay || replay.Receipt != first.Receipt || replay.Current != first.Current {
		t.Fatalf("same command must replay without writes: %v", err)
	}

	for _, revision := range []uint64{3, 4} {
		t.Run(strconv.FormatUint(revision, 10), func(t *testing.T) {
			suspend := mentorTestCommand(MentorRoleDecisionSuspend, revision)
			snapshot := mentorTestSnapshot(first)
			before := *snapshot.ApplicationFence
			revoked, err := PlanMentorRoleCommand(suspend, snapshot)
			if err != nil || !revoked.Write || revoked.Current.Active || !revoked.Current.Suspended || revoked.Current.Command != suspend {
				t.Fatalf("suspension must produce a terminal tombstone: %v", err)
			}
			if *snapshot.ApplicationFence != before || *snapshot.TargetFence != before {
				t.Fatal("pure planner mutated caller-owned snapshot")
			}
			after := mentorTestSnapshot(revoked)
			after.Receipt = &first.Receipt
			replay, err := PlanMentorRoleCommand(approve, after)
			if err != nil || replay.Write || !replay.Replay || replay.Receipt != first.Receipt || !replay.Receipt.Applied.Active || replay.Current.Active || !replay.Current.Suspended {
				t.Fatalf("historical approval replay must return current revoked state without restoring grant: %v", err)
			}
			after.Receipt = &revoked.Receipt
			replay, err = PlanMentorRoleCommand(suspend, after)
			if err != nil || replay.Write || !replay.Replay || replay.Receipt != revoked.Receipt || replay.Current != revoked.Current {
				t.Fatalf("suspend replay must preserve receipt and current tombstone: %v", err)
			}
		})
	}
}

func TestMentorRolePlanRevokeFirstRejectsDelayedApprovalAndTargetReparenting(t *testing.T) {
	for _, revision := range []uint64{3, 4} {
		t.Run(strconv.FormatUint(revision, 10), func(t *testing.T) {
			suspend := mentorTestCommand(MentorRoleDecisionSuspend, revision)
			revoked, err := PlanMentorRoleCommand(suspend, MentorRoleSnapshot{})
			if err != nil || !revoked.Write || revoked.Current.Active || !revoked.Current.Suspended {
				t.Fatalf("revoke-before-grant must persist a tombstone: %v", err)
			}
			snapshot := mentorTestSnapshot(revoked)
			assertMentorPlanDenied(t, mentorTestCommand(MentorRoleDecisionApprove, 2), snapshot, ErrMentorRoleStaleRevision)
			newApplication := mentorTestCommand(MentorRoleDecisionApprove, 2)
			newApplication.ApplicationID = "00000000-0000-4000-8000-000000000c02"
			newApplication.RequestID = "00000000-0000-4000-8000-000000000d03"
			newApplication = mentorTestDigest(newApplication)
			assertMentorPlanDenied(t, newApplication, MentorRoleSnapshot{TargetFence: snapshot.TargetFence}, ErrMentorRoleConflict)
			assertMentorPlanDenied(t, newApplication, snapshot, ErrMentorRoleConflict)
		})
	}
}

func TestMentorRolePlanRejectsReparentingConflictingReplayAndReactivation(t *testing.T) {
	approve := mentorTestCommand(MentorRoleDecisionApprove, 2)
	first, err := PlanMentorRoleCommand(approve, MentorRoleSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := mentorTestSnapshot(first)
	snapshot.Receipt = &first.Receipt
	for _, tc := range []struct {
		name   string
		mutate func(*MentorRoleCommand)
	}{
		{"target", func(c *MentorRoleCommand) { c.TargetUserID = "00000000-0000-4000-8000-000000000b02" }},
		{"admin", func(c *MentorRoleCommand) { c.AdminID = "00000000-0000-4000-8000-000000000a02" }},
		{"application", func(c *MentorRoleCommand) { c.ApplicationID = "00000000-0000-4000-8000-000000000c02" }},
		{"decision", func(c *MentorRoleCommand) { c.Decision = MentorRoleDecisionSuspend; c.ApplicationRevision = 3 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := approve
			tc.mutate(&changed)
			assertMentorPlanDenied(t, mentorTestDigest(changed), snapshot, ErrMentorRoleConflict)
		})
	}
	newRequest := approve
	newRequest.RequestID = mentorTestSuspendRequest
	assertMentorPlanDenied(t, mentorTestDigest(newRequest), mentorTestSnapshot(first), ErrMentorRoleConflict)
	newTarget := mentorTestCommand(MentorRoleDecisionSuspend, 3)
	newTarget.TargetUserID = "00000000-0000-4000-8000-000000000b02"
	assertMentorPlanDenied(t, newTarget, MentorRoleSnapshot{ApplicationFence: snapshot.ApplicationFence}, ErrMentorRoleConflict)
	revoked, err := PlanMentorRoleCommand(mentorTestCommand(MentorRoleDecisionSuspend, 3), MentorRoleSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	newSuspend := mentorTestCommand(MentorRoleDecisionSuspend, 4)
	newSuspend.RequestID = "00000000-0000-4000-8000-000000000d03"
	assertMentorPlanDenied(t, mentorTestDigest(newSuspend), mentorTestSnapshot(revoked), ErrMentorRoleConflict)
}

func TestMentorRolePlanRejectsMalformedOrIncompleteSnapshots(t *testing.T) {
	approve := mentorTestCommand(MentorRoleDecisionApprove, 2)
	first, err := PlanMentorRoleCommand(approve, MentorRoleSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	suspend := mentorTestCommand(MentorRoleDecisionSuspend, 4)
	wrongFence := first.Current
	wrongFence.Active = false
	differentFence := first.Current
	differentFence.Command.RequestID = mentorTestSuspendRequest
	differentFence.Command = mentorTestDigest(differentFence.Command)
	wrongReceipt := first.Receipt
	wrongReceipt.Applied.Active = false
	for _, tc := range []struct {
		name     string
		command  MentorRoleCommand
		snapshot MentorRoleSnapshot
	}{
		{"application only", suspend, MentorRoleSnapshot{ApplicationFence: &first.Current}},
		{"target only", suspend, MentorRoleSnapshot{TargetFence: &first.Current}},
		{"invalid fence state", suspend, MentorRoleSnapshot{ApplicationFence: &wrongFence, TargetFence: &wrongFence}},
		{"different fence views", suspend, MentorRoleSnapshot{ApplicationFence: &first.Current, TargetFence: &differentFence}},
		{"receipt without fences", approve, MentorRoleSnapshot{Receipt: &first.Receipt}},
		{"invalid historical receipt", approve, MentorRoleSnapshot{Receipt: &wrongReceipt, ApplicationFence: &first.Current, TargetFence: &first.Current}},
		{"wrong receipt key", suspend, MentorRoleSnapshot{Receipt: &first.Receipt, ApplicationFence: &first.Current, TargetFence: &first.Current}},
		{"missing receipt for applied command", approve, mentorTestSnapshot(first)},
	} {
		t.Run(tc.name, func(t *testing.T) { assertMentorPlanDenied(t, tc.command, tc.snapshot, ErrMentorRoleInvalidSnapshot) })
	}
	revoked, err := PlanMentorRoleCommand(suspend, mentorTestSnapshot(first))
	if err != nil {
		t.Fatal(err)
	}
	regressed := mentorTestSnapshot(first)
	regressed.Receipt = &revoked.Receipt
	assertMentorPlanDenied(t, suspend, regressed, ErrMentorRoleInvalidSnapshot)
}

func TestMentorRoleCommandValidationRejectsEveryAuthorityOrBindingEscape(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*MentorRoleCommand)
	}{
		{"issuer", func(c *MentorRoleCommand) { c.Issuer = "caller" }},
		{"role", func(c *MentorRoleCommand) { c.Role = "admin" }},
		{"service", func(c *MentorRoleCommand) { c.Service = "core" }},
		{"admin", func(c *MentorRoleCommand) { c.AdminID = "" }},
		{"target nil", func(c *MentorRoleCommand) { c.TargetUserID = "00000000-0000-0000-0000-000000000000" }},
		{"application uppercase", func(c *MentorRoleCommand) { c.ApplicationID = "00000000-0000-4000-8000-000000000C01" }},
		{"request invalid", func(c *MentorRoleCommand) { c.RequestID = "invalid" }},
		{"digest", func(c *MentorRoleCommand) { c.DecisionDigest = "abc" }},
		{"revision zero", func(c *MentorRoleCommand) { c.ApplicationRevision = 0 }},
		{"approved finalization revision", func(c *MentorRoleCommand) { c.ApplicationRevision = 3 }},
		{"reactivation revision", func(c *MentorRoleCommand) { c.ApplicationRevision = 5 }},
		{"unknown decision", func(c *MentorRoleCommand) { c.Decision = "REACTIVATE" }},
		{"suspend invalid revision", func(c *MentorRoleCommand) { c.Decision = MentorRoleDecisionSuspend }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := mentorTestCommand(MentorRoleDecisionApprove, 2)
			tc.mutate(&command)
			if ValidMentorRoleCommand(command) {
				t.Fatal("invalid command accepted")
			}
			assertMentorPlanDenied(t, command, MentorRoleSnapshot{}, ErrMentorRoleInvalidCommand)
		})
	}
	for _, tc := range []struct {
		decision string
		revision uint64
	}{{MentorRoleDecisionApprove, 2}, {MentorRoleDecisionSuspend, 3}, {MentorRoleDecisionSuspend, 4}} {
		if !ValidMentorRoleCommand(mentorTestCommand(tc.decision, tc.revision)) {
			t.Fatal("valid v1 binding was rejected")
		}
	}
}

func assertMentorPlanDenied(t *testing.T, command MentorRoleCommand, snapshot MentorRoleSnapshot, want error) {
	t.Helper()
	plan, err := PlanMentorRoleCommand(command, snapshot)
	if !errors.Is(err, want) || plan != (MentorRolePlan{}) {
		t.Fatalf("expected zero plan and %v, got %v", want, err)
	}
}
