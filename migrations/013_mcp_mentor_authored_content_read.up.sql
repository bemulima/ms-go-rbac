-- Register authoring scope markers without default grants.
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '5s';
SET LOCAL search_path = pg_catalog, public, pg_temp;
LOCK TABLE public.permission, public.mcp_mentor_workspace_read_permission IN SHARE ROW EXCLUSIVE MODE;
ALTER TABLE public.mcp_mentor_workspace_read_permission
  DROP CONSTRAINT mcp_mentor_workspace_read_permission_scope_check,
  ADD CONSTRAINT mcp_mentor_workspace_read_permission_scope_check CHECK (scope IN ('mentor:students:read', 'mentor:cohorts:read', 'mentor:schedule:read', 'mentor:skills:read', 'mentor:reviews:read','mentor:courses:read', 'mentor:tasks:read', 'mentor:notifications:read', 'mentor:dialogs:read'));
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
    IF EXISTS (SELECT 1 FROM public.permission WHERE action=entry.action AND resource_kind='') THEN
      RAISE EXCEPTION 'refusing adoption of existing Mentor authored content permission';
    END IF;
    INSERT INTO public.permission(action,resource_kind) VALUES (entry.action,'') RETURNING id INTO owned_permission;
    INSERT INTO public.mcp_mentor_workspace_read_permission(scope,permission_id) VALUES (entry.scope,owned_permission);
  END LOOP;
END;
$$;
