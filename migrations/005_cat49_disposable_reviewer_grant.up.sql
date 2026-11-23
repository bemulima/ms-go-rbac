-- Task-only, additive and immutable reviewer role receipt. No grant at migration.
CREATE TABLE cat49_disposable_reviewer_grant (
  request_id uuid PRIMARY KEY,
  principal_id uuid NOT NULL UNIQUE,
  run_id text NOT NULL UNIQUE CHECK (run_id ~ '^[a-z0-9]{8,32}$'),
  auth_receipt_digest text NOT NULL CHECK (auth_receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
  operator_name text NOT NULL CHECK (length(operator_name) BETWEEN 1 AND 64),
  applied_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION reject_cat49_reviewer_grant_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'CAT49 reviewer grant receipt is immutable';
END;
$$;
CREATE TRIGGER cat49_reviewer_grant_immutable BEFORE UPDATE OR DELETE ON cat49_disposable_reviewer_grant
 FOR EACH ROW EXECUTE FUNCTION reject_cat49_reviewer_grant_change();
