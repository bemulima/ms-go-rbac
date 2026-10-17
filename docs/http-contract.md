# HTTP contract

Public/principal endpoints use the methods and paths in .ai/contracts/http.yaml. Wrong methods return 404 in current handlers.

Admin get/update/list and role-permission routes follow the router and handlers. Service, role, and permission create handlers currently check for the literal method SET, so the POST routes formerly listed in wiki do not work. This is documented current behavior and should be fixed in a separate tested bugfix.

## Mutation admission

All eight existing mutation operations enforce admission in the handler before body decoding, usecase reads, replay checks or writes: PATCH principal-role/update; SET service, role and permission; PUT each definition by ID; and POST role-permission. This also applies to direct handler and child-router mounting. Existing GET reads remain public; methods and paths are unchanged.

A single `Authorization: Bearer <access credential>` header is required. RBAC sends POST JSON `{ "token": "<credential>" }` only to the operator-configured `AUTH_VERIFY_URL`, normally the existing Auth `/api/v1/auth/verify` endpoint. It consumes Auth's direct JSON response with `user_id` and `claims`, requiring a non-nil UUID identity, nonempty issuer/audience and future numeric expiry. Legacy access credentials may omit `typ` and `purpose`; each claim, when present, must be the string `access`. Caller identity/role/scope headers and locally decoded tokens do not establish authority.

Missing/malformed bearer or Auth rejection returns 401. Successfully verified access identities, including administrative role claims, return 403: administrative grants remain HUMAN_POLICY_DECISION_REQUIRED and every HTTP mutation is denied. Authority outage, timeout, redirect, unexpected status or malformed/oversized success response returns 503. None of these paths reads or changes mutation state, and errors do not expose credentials or authority response bodies. No public role-grant API is enabled.

There is no default authority, redirect following, environment proxy forwarding or verification fallback. `AUTH_VERIFY_URL` must be an absolute http/https endpoint without credentials, query or fragment; invalid nonempty configuration fails startup before database connection. Empty configuration preserves startup/public reads but returns 503 for supplied bearer mutations; missing bearer returns 401. Verification uses a three-second timeout and a 64 KiB response limit; bearer input is limited to 16 KiB.

NATS `rbac.assign-role` remains a separate dedicated Auth Ed25519-signed canonical STUDENT signup boundary under the [messaging contract](messaging-contract.md). HTTP identity verification adds no administrative grant to that flow and no unsigned/internal-caller fallback.
