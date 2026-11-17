-- Source-only until separately approved execution by ms-rbac-migrate.
-- The runner supplies one transaction, including the migration ledger.
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '5s';
SET LOCAL search_path = pg_catalog, public, pg_temp;
LOCK TABLE public.role, public.service, public.service_role IN SHARE ROW EXCLUSIVE MODE;

-- Record the generated identities so neither runtime nor DOWN adopts a
-- replacement row merely because it reuses the same logical key.
CREATE TABLE public.mentor_role_scope (
  singleton boolean PRIMARY KEY CHECK (singleton),
  role_id uuid NOT NULL UNIQUE REFERENCES public.role(id) ON DELETE RESTRICT
    CHECK (role_id <> '00000000-0000-0000-0000-000000000000'),
  service_id uuid NOT NULL UNIQUE REFERENCES public.service(id) ON DELETE RESTRICT
    CHECK (service_id NOT IN ('00000000-0000-0000-0000-000000000000',
                             '00000000-0000-0000-0000-000000000100')),
  UNIQUE (role_id, service_id)
);

DO $$
DECLARE
  owned_role_id uuid;
  owned_service_id uuid;
BEGIN
  IF EXISTS (SELECT 1 FROM public.role WHERE key = 'mentor')
     OR EXISTS (SELECT 1 FROM public.service WHERE key = 'ms-go-mentor') THEN
    RAISE EXCEPTION 'refusing adoption of existing Mentor metadata';
  END IF;
  INSERT INTO public.role (key, title) VALUES ('mentor', 'Mentor') RETURNING id INTO owned_role_id;
  INSERT INTO public.service (key, title) VALUES ('ms-go-mentor', 'Mentor Service') RETURNING id INTO owned_service_id;
  INSERT INTO public.service_role (role_id, service_id) VALUES (owned_role_id, owned_service_id);
  INSERT INTO public.mentor_role_scope (singleton, role_id, service_id)
    VALUES (true, owned_role_id, owned_service_id);
END;
$$;

CREATE TABLE public.mentor_role_command_receipt (
  issuer text NOT NULL CHECK (issuer = 'ms-go-auth'),
  request_id uuid NOT NULL CHECK (request_id <> '00000000-0000-0000-0000-000000000000'),
  admin_id uuid NOT NULL CHECK (admin_id <> '00000000-0000-0000-0000-000000000000'),
  target_user_id uuid NOT NULL CHECK (target_user_id <> '00000000-0000-0000-0000-000000000000'),
  application_id uuid NOT NULL CHECK (application_id <> '00000000-0000-0000-0000-000000000000'),
  application_revision bigint NOT NULL,
  decision text NOT NULL,
  decision_digest text NOT NULL CHECK (decision_digest ~ '^[0-9a-f]{64}$'),
  role_key text NOT NULL CHECK (role_key = 'mentor'),
  service_key text NOT NULL CHECK (service_key = 'ms-go-mentor'),
  role_id uuid NOT NULL,
  service_id uuid NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (issuer, request_id),
  UNIQUE (application_id, application_revision),
  UNIQUE (issuer, request_id, application_id, target_user_id, role_key, service_key,
          role_id, service_id, application_revision),
  FOREIGN KEY (role_id, service_id) REFERENCES public.mentor_role_scope (role_id, service_id)
    ON DELETE RESTRICT,
  CHECK ((decision = 'APPROVE' AND application_revision = 2)
      OR (decision = 'SUSPEND' AND application_revision IN (3, 4)))
);

-- One row provides both indexed views; they cannot diverge independently.
-- Its current command is an exact immutable receipt, not an unsigned boolean.
CREATE TABLE public.mentor_role_fence (
  application_id uuid PRIMARY KEY,
  issuer text NOT NULL CHECK (issuer = 'ms-go-auth'),
  target_user_id uuid NOT NULL,
  role_key text NOT NULL CHECK (role_key = 'mentor'),
  service_key text NOT NULL CHECK (service_key = 'ms-go-mentor'),
  role_id uuid NOT NULL,
  service_id uuid NOT NULL,
  application_revision bigint NOT NULL CHECK (application_revision IN (2, 3, 4)),
  request_id uuid NOT NULL,
  UNIQUE (target_user_id, role_key, service_key),
  FOREIGN KEY (issuer, request_id, application_id, target_user_id, role_key, service_key,
               role_id, service_id, application_revision)
    REFERENCES public.mentor_role_command_receipt
      (issuer, request_id, application_id, target_user_id, role_key, service_key,
       role_id, service_id, application_revision) ON DELETE RESTRICT
);

CREATE FUNCTION public.reject_mentor_role_owner_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'Mentor role receipts and owned scope metadata are immutable';
END;
$$;
CREATE TRIGGER mentor_role_scope_immutable
  BEFORE UPDATE OR DELETE OR TRUNCATE ON public.mentor_role_scope
  FOR EACH STATEMENT EXECUTE FUNCTION public.reject_mentor_role_owner_mutation();
CREATE TRIGGER mentor_role_receipt_immutable
  BEFORE UPDATE OR DELETE OR TRUNCATE ON public.mentor_role_command_receipt
  FOR EACH STATEMENT EXECUTE FUNCTION public.reject_mentor_role_owner_mutation();
CREATE TRIGGER mentor_role_fence_no_truncate
  BEFORE TRUNCATE ON public.mentor_role_fence
  FOR EACH STATEMENT EXECUTE FUNCTION public.reject_mentor_role_owner_mutation();

CREATE FUNCTION public.guard_mentor_role_fence_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Mentor role fence tombstones cannot be deleted';
  END IF;
  IF ROW(NEW.application_id, NEW.issuer, NEW.target_user_id, NEW.role_key, NEW.service_key,
         NEW.role_id, NEW.service_id)
     IS DISTINCT FROM
     ROW(OLD.application_id, OLD.issuer, OLD.target_user_id, OLD.role_key, OLD.service_key,
         OLD.role_id, OLD.service_id) THEN
    RAISE EXCEPTION 'Mentor role fence binding is immutable';
  END IF;
  IF OLD.application_revision <> 2 OR NEW.application_revision NOT IN (3, 4)
     OR NEW.request_id = OLD.request_id THEN
    RAISE EXCEPTION 'Mentor role fence is terminal or transition is invalid';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER mentor_role_fence_transition
  BEFORE UPDATE OR DELETE ON public.mentor_role_fence
  FOR EACH ROW EXECUTE FUNCTION public.guard_mentor_role_fence_mutation();
