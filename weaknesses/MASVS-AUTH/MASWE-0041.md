---
title: Authentication Enforced Only Locally Instead of on the Server-side
id: MASWE-0041
alias: local-auth-enforcement
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-AUTH-1]
  masvs-v2: [MASVS-AUTH-2]
  cwe: [603, 287]

draft:
  description: General authentication best practice. Only for apps with connection.
    The app performs local authentication involving the remote endpoint and according
    to the platform best practices.
  topics:
  - (IEEE) Since client-side security controls are capable of being invaded, authentication
    and authorization controls should be implemented on the server-side.
  - biometry only used as part of MFA authentication and not as the only auth method
status: placeholder

---

