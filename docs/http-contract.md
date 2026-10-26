# HTTP contract

Public/principal endpoints use the methods and paths in .ai/contracts/http.yaml. Wrong methods return 404 in current handlers.

Admin get/update/list and role-permission routes follow the router and handlers. Service, role, and permission create handlers currently check for the literal method SET, so the POST routes formerly listed in wiki do not work. This is documented current behavior and should be fixed in a separate tested bugfix.

All HTTP mutations are now unconditionally denied with 403 at the owner router, before decoding or dispatch, including PATCH /api/v1/principal-role/update and admin POST/PUT/DELETE/SET. No bearer, actor header, shared token, or ADMIN/MODERATOR role can authorize these legacy HTTP writes. There is no trustworthy HTTP role-management actor contract, so no header-only authorization was added. GET/HEAD/OPTIONS retain existing read/method behavior; /admin is not an authentication boundary for reads. Signed NATS student provisioning remains unchanged.

Administrative initial grants use only the standalone [operator bootstrap CLI](operator-bootstrap.md). This source change is not effective until an explicitly approved rollout; the existing persistent runtime remains EXPOSED.
