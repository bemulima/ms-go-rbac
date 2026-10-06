CREATE TABLE signup_provisioning_receipt (
  issuer text NOT NULL CHECK (issuer = 'ms-go-auth'),
  operation_id uuid NOT NULL CHECK (operation_id <> '00000000-0000-0000-0000-000000000000'),
  principal_id uuid NOT NULL CHECK (principal_id <> '00000000-0000-0000-0000-000000000000'),
  role_key text NOT NULL CHECK (role_key = 'student'),
  principal_kind text NOT NULL CHECK (principal_kind = 'user'),
  tenant_id uuid NOT NULL CHECK (tenant_id = '00000000-0000-0000-0000-000000000000'),
  service_id uuid NOT NULL CHECK (service_id = '00000000-0000-0000-0000-000000000100'),
  resource_kind text NOT NULL CHECK (resource_kind = 'global'),
  resource_id uuid NOT NULL CHECK (resource_id = '00000000-0000-0000-0000-000000000000'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (issuer, operation_id),
  UNIQUE (issuer, principal_id)
);

CREATE FUNCTION reject_signup_receipt_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'signup provisioning receipts are immutable';
END;
$$;

CREATE TRIGGER signup_receipt_immutable
BEFORE UPDATE OR DELETE ON signup_provisioning_receipt
FOR EACH ROW EXECUTE FUNCTION reject_signup_receipt_mutation();
