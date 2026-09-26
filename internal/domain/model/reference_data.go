package model

// CanonicalRoles returns the RBAC-owned reference roles provisioned in every
// newly prepared schema. Return a copy so callers cannot mutate the source of
// truth shared by other packages.
func CanonicalRoles() []Role {
	return []Role{
		{Key: "admin", Title: "Admin"},
		{Key: "moderator", Title: "Moderator"},
		{Key: "teacher", Title: "Teacher"},
		{Key: "student", Title: "Student"},
		{Key: "user", Title: "User"},
		{Key: "guest", Title: "Guest"},
	}
}

// CanonicalCoreService returns the shared service metadata used by global RBAC
// assignments. Its stable ID matches the existing RBAC seed contract.
func CanonicalCoreService() Service {
	return Service{
		ID:    "00000000-0000-0000-0000-000000000100",
		Key:   "core",
		Title: "Core Service",
	}
}
