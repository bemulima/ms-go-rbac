create extension if not exists pgcrypto;

create table service (
  id uuid primary key default gen_random_uuid(),
  key text unique not null,
  title text not null
);

create table role (
  id uuid primary key default gen_random_uuid(),
  key text not null,
  title text not null,
  unique (key)
);

create table role_hierarchy (
  role_id uuid not null references role(id) on delete cascade,
  parent_role_id uuid not null references role(id) on delete cascade,
  primary key (role_id, parent_role_id),
  check (role_id <> parent_role_id)
);

create table permission (
  id uuid primary key default gen_random_uuid(),
  action text not null,
  resource_kind text not null,
  unique (action, resource_kind)
);

create table role_permission (
  role_id uuid not null references role(id) on delete cascade,
  permission_id uuid not null references permission(id) on delete cascade,
  resource_id uuid,
  primary key (role_id, permission_id, resource_id)
);

create table service_role (
  role_id uuid not null references role(id) on delete cascade,
  service_id uuid not null references service(id) on delete cascade,
  primary key (role_id, service_id)
);

create table service_permission (
  permission_id uuid not null references permission(id) on delete cascade,
  service_id uuid not null references service(id) on delete cascade,
  primary key (permission_id, service_id)
);

create type principal_kind as enum ('user','service_account','group');

create table principal_role (
  principal_id uuid not null,
  principal_kind principal_kind not null,
  role_id uuid not null references role(id) on delete cascade,

  tenant_id uuid,
  service_id uuid,
  resource_kind text,
  resource_id uuid,

  primary key (principal_id, principal_kind, role_id, tenant_id, service_id, resource_kind, resource_id),
  foreign key (service_id) references service(id) on delete cascade
);

create type override_effect as enum ('allow','deny');

create table principal_override (
  principal_id uuid not null,
  principal_kind principal_kind not null,
  permission_id uuid not null references permission(id) on delete cascade,
  effect override_effect not null,

  tenant_id uuid,
  service_id uuid,
  resource_kind text,
  resource_id uuid,

  primary key (principal_id, principal_kind, permission_id, tenant_id, service_id, resource_kind, resource_id),
  foreign key (service_id) references service(id) on delete cascade
);

create table superadmin_principal (
  principal_id uuid primary key,
  principal_kind principal_kind not null
);

create index on principal_role (principal_id, principal_kind, tenant_id, service_id, resource_kind, resource_id);
create index on principal_override (principal_id, principal_kind, tenant_id, service_id, resource_kind, resource_id);
