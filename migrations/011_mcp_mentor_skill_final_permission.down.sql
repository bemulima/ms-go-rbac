SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '10s';
SET LOCAL search_path = pg_catalog,public,pg_temp;
LOCK TABLE public.permission, public.role_permission, public.service_permission, public.principal_override IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE public.mcp_mentor_skill_final_review_permission IN ACCESS EXCLUSIVE MODE;
DO $$
DECLARE item record;
BEGIN
  FOR item IN SELECT permission_id FROM public.mcp_mentor_skill_final_review_permission LOOP
    IF EXISTS (SELECT 1 FROM public.role_permission WHERE permission_id=item.permission_id)
      OR EXISTS (SELECT 1 FROM public.service_permission WHERE permission_id=item.permission_id)
      OR EXISTS (SELECT 1 FROM public.principal_override WHERE permission_id=item.permission_id) THEN
      RAISE EXCEPTION 'explicit references prevent Mentor MCP permission rollback';
    END IF;
    DELETE FROM public.mcp_mentor_skill_final_review_permission WHERE permission_id=item.permission_id;
    DELETE FROM public.permission WHERE id=item.permission_id;
  END LOOP;
END;
$$;
DROP TABLE public.mcp_mentor_skill_final_review_permission;
