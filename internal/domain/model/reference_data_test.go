package model

import "testing"

func TestCanonicalRolesAreTheCompleteSeededRoleSet(t *testing.T) {
	want := map[string]string{
		"admin":     "Admin",
		"moderator": "Moderator",
		"teacher":   "Teacher",
		"student":   "Student",
		"user":      "User",
		"guest":     "Guest",
	}

	roles := CanonicalRoles()
	if len(roles) != len(want) {
		t.Fatalf("canonical role count = %d, want %d", len(roles), len(want))
	}
	for _, role := range roles {
		title, ok := want[role.Key]
		if !ok {
			t.Errorf("unexpected canonical role %q", role.Key)
			continue
		}
		if role.Title != title {
			t.Errorf("canonical role %q title = %q, want %q", role.Key, role.Title, title)
		}
		delete(want, role.Key)
	}
	if len(want) != 0 {
		t.Errorf("canonical roles missing: %v", want)
	}
}

func TestCanonicalCoreServiceMatchesLegacyReference(t *testing.T) {
	service := CanonicalCoreService()
	if service.ID != "00000000-0000-0000-0000-000000000100" || service.Key != "core" || service.Title != "Core Service" {
		t.Fatalf("unexpected canonical core service: %#v", service)
	}
}
