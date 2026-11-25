-- Metadata only. No role, principal or permission assignment is granted.
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '5s';
SET LOCAL search_path = pg_catalog, public, pg_temp;
LOCK TABLE public.permission IN SHARE ROW EXCLUSIVE MODE;
CREATE TABLE public.mcp_mentor_offers_permission (
  singleton boolean PRIMARY KEY CHECK (singleton),
  permission_id uuid NOT NULL UNIQUE REFERENCES public.permission(id) ON DELETE RESTRICT
);
DO $$
DECLARE owned_permission uuid;
BEGIN
  IF EXISTS (SELECT 1 FROM public.permission WHERE action='mcp.mentor.offers.read' AND resource_kind='') THEN
    RAISE EXCEPTION 'refusing adoption of existing MCP Mentor permission';
  END IF;
  INSERT INTO public.permission(action,resource_kind) VALUES ('mcp.mentor.offers.read','') RETURNING id INTO owned_permission;
  INSERT INTO public.mcp_mentor_offers_permission(singleton,permission_id) VALUES (true,owned_permission);
END;
$$;
