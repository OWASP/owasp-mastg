---
title: Authentication Tokens Not Validated
id: MASWE-0038
alias: unvalidated-auth-tokens
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-AUTH-3]
  masvs-v2: [MASVS-AUTH-1, MASVS-CODE-4]
  cwe: [287]

refs:
- https://developers.google.com/identity/sign-in/android/backend-auth#verify-the-integrity-of-the-id-token
- https://developers.google.com/identity/protocols/oauth2/openid-connect#validatinganidtoken
- https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
draft:
  description: e.g. oauth2/jwt client-side checks
  topics:
  - code grant
  - expiration
  - none algorithm
  - PKCE
  - implicit grant
status: placeholder

---

