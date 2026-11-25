SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '10s';
SET LOCAL search_path = pg_catalog,public,pg_temp;
LOCK TABLE public.permission IN SHARE ROW EXCLUSIVE MODE;
CREATE TABLE public.mcp_mentor_skill_final_review_permission (
  scope text PRIMARY KEY CHECK (scope IN ('mentor:skills:publish','mentor:reviews:write','mentor:reviews:decide')),
  permission_id uuid NOT NULL UNIQUE REFERENCES public.permission(id)
);
DO $$
DECLARE
  item record;
  owned_permission uuid;
BEGIN
  FOR item IN SELECT * FROM (VALUES
    ('mentor:skills:publish','mcp.mentor.skills.publish'),
    ('mentor:reviews:write','mcp.mentor.reviews.write'),
    ('mentor:reviews:decide','mcp.mentor.reviews.decide')
  ) AS v(scope,action) LOOP
    IF EXISTS (SELECT 1 FROM public.permission WHERE action=item.action AND resource_kind='') THEN
      RAISE EXCEPTION 'pre-existing unowned Mentor MCP permission';
    END IF;
    INSERT INTO public.permission(action,resource_kind) VALUES (item.action,'') RETURNING id INTO owned_permission;
    INSERT INTO public.mcp_mentor_skill_final_review_permission(scope,permission_id) VALUES (item.scope,owned_permission);
  END LOOP;
END;
$$;
