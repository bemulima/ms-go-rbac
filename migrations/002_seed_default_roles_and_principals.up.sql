-- Seed default roles and assign them to default principals from ms-go-user.

INSERT INTO role (key, title)
VALUES
    ('admin', 'Admin'),
    ('manager', 'Manager'),
    ('teacher', 'Teacher'),
    ('student', 'Student'),
    ('user', 'User'),
    ('guest', 'Guest')
ON CONFLICT (key) DO NOTHING;

WITH svc AS (
    INSERT INTO service (id, key, title)
    VALUES ('00000000-0000-0000-0000-000000000100', 'core', 'Core Service')
    ON CONFLICT (key) DO UPDATE SET title = excluded.title
    RETURNING id
),
role_ids AS (
    SELECT key, id FROM role WHERE key IN ('admin','manager','teacher','student','user')
),
assignments AS (
    SELECT * FROM (VALUES
        ('00000000-0000-0000-0000-0000000000a1'::uuid, 'admin'),
        ('00000000-0000-0000-0000-0000000000a2'::uuid, 'manager'),
        ('00000000-0000-0000-0000-0000000000a3'::uuid, 'teacher'),
        ('00000000-0000-0000-0000-0000000000b1'::uuid, 'student'),
        ('00000000-0000-0000-0000-0000000000b2'::uuid, 'student'),
        ('00000000-0000-0000-0000-0000000000b3'::uuid, 'student'),
        ('00000000-0000-0000-0000-0000000000c1'::uuid, 'user')
    ) AS t(principal_id, role_key)
)
INSERT INTO principal_role (
    principal_id,
    principal_kind,
    role_id,
    tenant_id,
    service_id,
    resource_kind,
    resource_id
)
SELECT
    a.principal_id,
    'user'::principal_kind,
    r.id,
    '00000000-0000-0000-0000-000000000000'::uuid AS tenant_id,
    (SELECT id FROM svc) AS service_id,
    'global' AS resource_kind,
    '00000000-0000-0000-0000-000000000000'::uuid AS resource_id
FROM assignments a
JOIN role_ids r ON r.key = a.role_key
ON CONFLICT DO NOTHING;
