# HTTP contract

Public/principal endpoints use the methods and paths in .ai/contracts/http.yaml. Wrong methods return 404 in current handlers.

Admin get/update/list and role-permission routes follow the router and handlers. Service, role, and permission create handlers currently check for the literal method SET, so the POST routes formerly listed in wiki do not work. This is documented current behavior and should be fixed in a separate tested bugfix.

No HTTP authentication middleware is installed. Do not infer protection from the /admin prefix.
