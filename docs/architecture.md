# Architecture

The active service exposes HTTP CRUD/principal lookups and two Core NATS role RPC handlers backed by PostgreSQL repositories. It does not currently expose a complete policy-decision endpoint.

A PDP engine and PostgreSQL PDP repository exist, including superadmin, override-specificity, scoped-role, and permission matching logic. They are not wired into bootstrap, and the repository methods take context while the domain Repository interface does not. Therefore former wiki claims that PDP and overrides are fully active are intent/historical documentation, not current runtime behavior.

The current HTTP router installs no authentication or authorization middleware. This makes both API and admin routes directly callable on the service network and is a high-priority security defect.
