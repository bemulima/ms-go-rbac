-- Register exact RBAC permission metadata without granting access.
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '5s';
SET LOCAL search_path = pg_catalog, public, pg_temp;
LOCK TABLE public.permission IN SHARE ROW EXCLUSIVE MODE;
CREATE TABLE public.mcp_mentor_workspace_read_permission (
  scope text PRIMARY KEY CHECK (scope IN ('mentor:students:read', 'mentor:cohorts:read', 'mentor:schedule:read', 'mentor:skills:read', 'mentor:reviews:read')),
  permission_id uuid NOT NULL UNIQUE REFERENCES public.permission(id) ON DELETE RESTRICT
);
DO $$
DECLARE
  entry record;
  owned_permission uuid;
BEGIN
  FOR entry IN SELECT * FROM (VALUES
  ('mentor:students:read','mcp.mentor.students.read'),
  ('mentor:cohorts:read','mcp.mentor.cohorts.read'),
  ('mentor:schedule:read','mcp.mentor.schedule.read'),
  ('mentor:skills:read','mcp.mentor.skills.read'),
  ('mentor:reviews:read','mcp.mentor.reviews.read')
  ) AS supported(scope, action) LOOP
    IF EXISTS (SELECT 1 FROM public.permission WHERE action=entry.action AND resource_kind='') THEN
      RAISE EXCEPTION 'refusing adoption of existing Mentor workspace permission';
    END IF;
    INSERT INTO public.permission(action,resource_kind) VALUES (entry.action,'') RETURNING id INTO owned_permission;
    INSERT INTO public.mcp_mentor_workspace_read_permission(scope,permission_id) VALUES (entry.scope,owned_permission);
  END LOOP;
END;
$$;
