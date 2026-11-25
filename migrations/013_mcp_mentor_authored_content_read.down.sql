SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '5s';
SET LOCAL search_path = pg_catalog, public, pg_temp;
LOCK TABLE public.permission, public.role_permission, public.service_permission, public.principal_override, public.mcp_mentor_workspace_read_permission IN SHARE ROW EXCLUSIVE MODE;
DO $$
DECLARE
  entry record;
  owned_permission uuid;
BEGIN
  FOR entry IN SELECT * FROM (VALUES
    ('mentor:courses:read','mcp.mentor.courses.read'),
    ('mentor:tasks:read','mcp.mentor.tasks.read'),
    ('mentor:notifications:read','mcp.mentor.notifications.read'),
    ('mentor:dialogs:read','mcp.mentor.dialogs.read')
  ) AS supported(scope, action) LOOP
    SELECT marker.permission_id INTO STRICT owned_permission FROM public.mcp_mentor_workspace_read_permission marker
      JOIN public.permission p ON p.id=marker.permission_id WHERE marker.scope=entry.scope AND p.action=entry.action AND p.resource_kind='';
    IF EXISTS(SELECT 1 FROM public.role_permission WHERE permission_id=owned_permission)
      OR EXISTS(SELECT 1 FROM public.service_permission WHERE permission_id=owned_permission)
      OR EXISTS(SELECT 1 FROM public.principal_override WHERE permission_id=owned_permission) THEN
      RAISE EXCEPTION 'Mentor authored content permission still has explicit assignments';
    END IF;
    DELETE FROM public.mcp_mentor_workspace_read_permission WHERE permission_id=owned_permission;
    DELETE FROM public.permission WHERE id=owned_permission;
  END LOOP;
END;
$$;
ALTER TABLE public.mcp_mentor_workspace_read_permission
  DROP CONSTRAINT mcp_mentor_workspace_read_permission_scope_check,
  ADD CONSTRAINT mcp_mentor_workspace_read_permission_scope_check CHECK (scope IN ('mentor:students:read', 'mentor:cohorts:read', 'mentor:schedule:read', 'mentor:skills:read', 'mentor:reviews:read'));
