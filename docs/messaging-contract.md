# Messaging contract

rbac.assign-role and rbac.checkRole are queue-group Core NATS request/reply subjects. Both accept user_id and role. Responses contain ok and optional error. Assignment updates the principal role by role key; checkRole performs the current principal-role lookup.

They are RPC contracts, not durable events. Payload or semantics changes require consumer verification in auth, user, gateway, and other callers.
