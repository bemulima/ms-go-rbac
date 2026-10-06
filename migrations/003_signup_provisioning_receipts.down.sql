LOCK TABLE signup_provisioning_receipt IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM signup_provisioning_receipt) THEN
    RAISE EXCEPTION 'refusing rollback of nonempty signup provisioning receipts';
  END IF;
END;
$$;
DROP TABLE signup_provisioning_receipt;
DROP FUNCTION reject_signup_receipt_mutation();
