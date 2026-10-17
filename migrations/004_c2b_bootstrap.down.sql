BEGIN;
LOCK TABLE c2b_rbac_bootstrap_audit IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN IF EXISTS(SELECT 1 FROM c2b_rbac_bootstrap_audit) THEN RAISE EXCEPTION 'refuse rollback with retained bootstrap'; END IF; END $$;
DROP TABLE c2b_rbac_bootstrap_audit;
DROP FUNCTION c2b_rbac_bootstrap_immutable();
COMMIT;
