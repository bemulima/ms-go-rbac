# CAT-49 reviewer operator CLI (not activated)

This dedicated CLI is separate from the existing ms-rbac-operator-bootstrap.
It cannot connect to the canonical lw_rbac database and cannot be called over
HTTP, NATS, Gateway, startup or from the old V1 STUDENT-only fixture.

It is deliberately default-OFF. No reviewed execution approval is stored in
this repository. Before using it, an authorized independent security/operator
review must accept the exact source, signed CAT-49 ownership marker, private
operator key custody and task-local database/VM. The prior automated refusal
for the unrelated Auth V1 student fixture remains binding.

The operator reads one canonical signed Auth registration proof from stdin.
An independent dedicated Auth owner must have registered that principal as
PENDING through its own atomic owner transaction; this CLI does not create
credentials. The RBAC repository grants only one fresh MODERATOR in one run,
requires zero pre-existing roles and signs a replay-stable receipt after its
atomic grant transaction. Exact current RBAC role must be verified again
before Auth activation; this CLI does not issue Auth tokens.

Run source tests and scoped disposable database guard/receipt tests before
any real invocation. Never print DSN, HMAC keys or credentials, and do not
use the shared RBAC database or weaken the old CLI guards.
