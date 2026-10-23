DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM operator_bootstrap_receipt) THEN
  RAISE EXCEPTION 'retain operator receipts and assignments; populated rollback forbidden';
 END IF;
END; $$;
DROP TABLE operator_bootstrap_receipt;
DROP FUNCTION reject_operator_bootstrap_receipt_change();
