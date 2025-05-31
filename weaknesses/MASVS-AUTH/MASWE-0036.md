---
title: Authentication Material Stored Unencrypted on the Device
id: MASWE-0036
alias: auth-material-unencrypted
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v2: [MASVS-AUTH-1, MASVS-STORAGE-1]
  cwe: [312]

refs:
- https://developers.google.com/identity/blockstore/android?hl=en
- https://cloud.google.com/docs/authentication/best-practices-applications#semi-trusted_or_restricted_environments
- https://cloud.google.com/docs/authentication/best-practices-applications#security_considerations
- https://developer.apple.com/documentation/signinwithapplerestapi
draft:
  description: General authentication material management best practices. Note that API keys are covered separately.
  topics:
  - session IDs
  - tokens
  - passwords
  - use of sign-in with Apple/Google
status: placeholder

---

