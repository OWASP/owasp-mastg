---
title: Step-Up Authentication Not Implemented After Login
id: MASWE-0029
alias: step-up-auth
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-AUTH-10]
  masvs-v2: [MASVS-AUTH-3, MASVS-PLATFORM-3]
  cwe: [306]

refs:
- https://developer.apple.com/documentation/localauthentication
- https://auth0.com/blog/what-is-step-up-authentication-when-to-use-it/
- https://tdcolvin.medium.com/is-firebase-auth-secure-dace0563d41b
- https://github.com/WICG/trust-token-api
- https://blog.cloudflare.com/eliminating-captchas-on-iphones-and-macs-using-new-standard/
draft:
  description: An example of step-up authentication is when a user is logged into
    their bank account (with or without MFA) and requests an action that is considered
    sensitive, such as the transfer of a large sum of money. In such cases, the user
    will be required to provide additional information to authenticate their identity
    (e.g. using MFA) and ensure only the legitimate user is requesting the action.
  topics:
  - (ioXt) UP107 App shall re-authenticate the user when displaying sensitive PII
    data or conducting sensitive transactions.
  - null
status: placeholder

---

