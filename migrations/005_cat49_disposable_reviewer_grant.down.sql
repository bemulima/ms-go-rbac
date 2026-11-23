DO $$
BEGIN
 IF EXISTS(SELECT 1 FROM cat49_disposable_reviewer_grant) THEN
  RAISE EXCEPTION 'CAT49 reviewer grant receipts exist; rollback denied';
 END IF;
END;
$$;
DROP TABLE cat49_disposable_reviewer_grant;
DROP FUNCTION reject_cat49_reviewer_grant_change();
