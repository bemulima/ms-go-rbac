SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '5s';
SET LOCAL search_path = pg_catalog, public, pg_temp;
LOCK TABLE public.permission, public.role_permission, public.service_permission, public.principal_override, public.mcp_mentor_dialog_write_permission IN SHARE ROW EXCLUSIVE MODE;
DO $$
DECLARE owned_permission uuid;
BEGIN
  SELECT marker.permission_id INTO STRICT owned_permission FROM public.mcp_mentor_dialog_write_permission marker
    JOIN public.permission p ON p.id=marker.permission_id
    WHERE marker.singleton AND p.action='mcp.mentor.dialogs.write' AND p.resource_kind='';
  IF EXISTS(SELECT 1 FROM public.role_permission WHERE permission_id=owned_permission)
    OR EXISTS(SELECT 1 FROM public.service_permission WHERE permission_id=owned_permission)
    OR EXISTS(SELECT 1 FROM public.principal_override WHERE permission_id=owned_permission) THEN
    RAISE EXCEPTION 'MCP Mentor permission still has explicit assignments';
  END IF;
  DELETE FROM public.mcp_mentor_dialog_write_permission WHERE permission_id=owned_permission;
  DELETE FROM public.permission WHERE id=owned_permission;
END;
$$;
DROP TABLE public.mcp_mentor_dialog_write_permission;
