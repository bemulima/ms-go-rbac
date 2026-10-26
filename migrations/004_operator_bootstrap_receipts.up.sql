-- Explicit operator CLI only; does not grant or alter any existing role.
CREATE TABLE operator_bootstrap_receipt (
 request_id uuid PRIMARY KEY,
 principal_id uuid NOT NULL UNIQUE,
 role_key text NOT NULL CHECK (role_key IN ('moderator','admin')),
 expected_role text NOT NULL CHECK (expected_role = 'student'),
 operator_name text NOT NULL,
 environment text NOT NULL CHECK (environment = 'learning-workspace-local'),
 applied_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION reject_operator_bootstrap_receipt_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'operator bootstrap receipts are immutable'; END; $$;
CREATE TRIGGER operator_bootstrap_receipt_immutable BEFORE UPDATE OR DELETE ON operator_bootstrap_receipt
 FOR EACH ROW EXECUTE FUNCTION reject_operator_bootstrap_receipt_change();
