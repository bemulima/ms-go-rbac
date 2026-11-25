-- Register exact RBAC permission metadata without granting access.
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '5s';
SET LOCAL search_path = pg_catalog, public, pg_temp;
LOCK TABLE public.permission IN SHARE ROW EXCLUSIVE MODE;
CREATE TABLE public.mcp_mentor_management_permission (
  scope text PRIMARY KEY CHECK (scope IN ('mentor:profile:write', 'mentor:offers:write', 'mentor:students:write', 'mentor:cohorts:write', 'mentor:schedule:write', 'mentor:offers:publish', 'mentor:schedule:cancel')),
  permission_id uuid NOT NULL UNIQUE REFERENCES public.permission(id) ON DELETE RESTRICT
);
DO $$
DECLARE
  entry record;
  owned_permission uuid;
BEGIN
  FOR entry IN SELECT * FROM (VALUES
  ('mentor:profile:write','mcp.mentor.profile.write'),
  ('mentor:offers:write','mcp.mentor.offers.write'),
  ('mentor:students:write','mcp.mentor.students.write'),
  ('mentor:cohorts:write','mcp.mentor.cohorts.write'),
  ('mentor:schedule:write','mcp.mentor.schedule.write'),
  ('mentor:offers:publish','mcp.mentor.offers.publish'),
  ('mentor:schedule:cancel','mcp.mentor.schedule.cancel')
  ) AS supported(scope, action) LOOP
    IF EXISTS (SELECT 1 FROM public.permission WHERE action=entry.action AND resource_kind='') THEN
      RAISE EXCEPTION 'refusing adoption of existing Mentor management permission';
    END IF;
    INSERT INTO public.permission(action,resource_kind) VALUES (entry.action,'') RETURNING id INTO owned_permission;
    INSERT INTO public.mcp_mentor_management_permission(scope,permission_id) VALUES (entry.scope,owned_permission);
  END LOOP;
END;
$$;
