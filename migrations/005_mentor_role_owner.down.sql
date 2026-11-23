-- Empty, still-owned metadata only. The runner owns the transaction and ledger.
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '5s';
SET LOCAL search_path = pg_catalog, public, pg_temp;
-- Metadata-first matches the application lock order. Lock every known usage
-- table before examining it; a concurrent new reference must not be removed.
LOCK TABLE public.role, public.service, public.service_role IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE public.mentor_role_scope, public.principal_role,
  public.mentor_role_command_receipt, public.mentor_role_fence IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.role_hierarchy, public.role_permission,
  public.service_permission, public.principal_override IN SHARE ROW EXCLUSIVE MODE;

DO $$
DECLARE
  owned_role_id uuid;
  owned_service_id uuid;
BEGIN
  IF EXISTS (SELECT 1 FROM public.mentor_role_command_receipt)
     OR EXISTS (SELECT 1 FROM public.mentor_role_fence) THEN
    RAISE EXCEPTION 'refusing rollback of nonempty Mentor role history';
  END IF;
  SELECT role_id, service_id INTO STRICT owned_role_id, owned_service_id
    FROM public.mentor_role_scope WHERE singleton = true;
  IF NOT EXISTS (SELECT 1 FROM public.role WHERE id = owned_role_id AND key = 'mentor' AND title = 'Mentor')
     OR NOT EXISTS (SELECT 1 FROM public.service WHERE id = owned_service_id AND key = 'ms-go-mentor' AND title = 'Mentor Service')
     OR NOT EXISTS (SELECT 1 FROM public.service_role WHERE role_id = owned_role_id AND service_id = owned_service_id) THEN
    RAISE EXCEPTION 'refusing rollback of drifted Mentor metadata';
  END IF;
  IF EXISTS (SELECT 1 FROM public.principal_role WHERE role_id = owned_role_id OR service_id = owned_service_id)
     OR EXISTS (SELECT 1 FROM public.role_hierarchy WHERE role_id = owned_role_id OR parent_role_id = owned_role_id)
     OR EXISTS (SELECT 1 FROM public.role_permission WHERE role_id = owned_role_id)
     OR EXISTS (SELECT 1 FROM public.service_permission WHERE service_id = owned_service_id)
     OR EXISTS (SELECT 1 FROM public.principal_override WHERE service_id = owned_service_id)
     OR EXISTS (SELECT 1 FROM public.service_role
                WHERE (role_id = owned_role_id OR service_id = owned_service_id)
                  AND NOT (role_id = owned_role_id AND service_id = owned_service_id)) THEN
    RAISE EXCEPTION 'refusing rollback of referenced Mentor metadata';
  END IF;
  -- A later schema may add foreign-key consumers with destructive delete
  -- actions. Refuse unfamiliar consumers instead of guessing their ownership.
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint c
    WHERE c.contype = 'f'
      AND c.confrelid IN ('public.role'::regclass, 'public.service'::regclass)
      AND NOT EXISTS (
        SELECT 1 FROM (VALUES
          ('public.role_hierarchy'::regclass, 'role_id', 'public.role'::regclass, 'id'),
          ('public.role_hierarchy'::regclass, 'parent_role_id', 'public.role'::regclass, 'id'),
          ('public.role_permission'::regclass, 'role_id', 'public.role'::regclass, 'id'),
          ('public.service_role'::regclass, 'role_id', 'public.role'::regclass, 'id'),
          ('public.service_role'::regclass, 'service_id', 'public.service'::regclass, 'id'),
          ('public.service_permission'::regclass, 'service_id', 'public.service'::regclass, 'id'),
          ('public.principal_role'::regclass, 'role_id', 'public.role'::regclass, 'id'),
          ('public.principal_role'::regclass, 'service_id', 'public.service'::regclass, 'id'),
          ('public.principal_override'::regclass, 'service_id', 'public.service'::regclass, 'id'),
          ('public.mentor_role_scope'::regclass, 'role_id', 'public.role'::regclass, 'id'),
          ('public.mentor_role_scope'::regclass, 'service_id', 'public.service'::regclass, 'id')
        ) known(source_relation, source_column, target_relation, target_column)
        JOIN pg_catalog.pg_attribute source_att
          ON source_att.attrelid = known.source_relation
         AND source_att.attname = known.source_column AND NOT source_att.attisdropped
        JOIN pg_catalog.pg_attribute target_att
          ON target_att.attrelid = known.target_relation
         AND target_att.attname = known.target_column AND NOT target_att.attisdropped
        WHERE c.conrelid = known.source_relation AND c.confrelid = known.target_relation
          AND c.conkey = ARRAY[source_att.attnum]
          AND c.confkey = ARRAY[target_att.attnum]
      )
  ) THEN
    RAISE EXCEPTION 'refusing rollback with unknown metadata references';
  END IF;
  DROP TABLE public.mentor_role_fence;
  DROP TABLE public.mentor_role_command_receipt;
  DROP TABLE public.mentor_role_scope;
  DELETE FROM public.service_role WHERE role_id = owned_role_id AND service_id = owned_service_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'Mentor service role identity changed'; END IF;
  DELETE FROM public.role WHERE id = owned_role_id AND key = 'mentor' AND title = 'Mentor';
  IF NOT FOUND THEN RAISE EXCEPTION 'Mentor role identity changed'; END IF;
  DELETE FROM public.service WHERE id = owned_service_id AND key = 'ms-go-mentor' AND title = 'Mentor Service';
  IF NOT FOUND THEN RAISE EXCEPTION 'Mentor service identity changed'; END IF;
END;
$$;
DROP FUNCTION public.guard_mentor_role_fence_mutation();
DROP FUNCTION public.reject_mentor_role_owner_mutation();
