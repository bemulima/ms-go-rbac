# Database contract

The schema owns services, roles and hierarchy, permissions, role-permission links, service restrictions, scoped principal roles, principal overrides, and superadmin principals. Migration 002 seeds six role keys and default principal assignments.

Role descriptions and a hierarchy diagram in the old wiki are not themselves enforced policy. Active authorization is determined by stored assignments and the code path that is actually wired.
