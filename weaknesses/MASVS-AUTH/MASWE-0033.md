---
title: Authentication or Authorization Protocol Security Best Practices Not Followed
id: MASWE-0033
alias: auth-protocol-best-practices
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v2: [MASVS-AUTH-1]
  cwe: [285, 287]

refs:
- https://mobidev.biz/blog/single-sign-on-sso-implementation-benefits-enterprise
- https://developers.google.com/identity/protocols/risc
- https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession/3237231-prefersephemeralwebbrowsersessio?language=objc
- https://developer.apple.com/videos/play/tech-talks/301
- https://developers.google.com/identity/protocols/oauth2
draft:
  description: For example, when using oauth2, the app does not use PKCE, etc. See
    RFC-8252. Focus on client-side best practices.
  topics:
  - best practices from RFC-8252
  - SSO -> OpenID Connect (OIDC)
  - use of Google Service Accounts
  - use of RISC
  - use of Apple Redirect extensions for Enterprise
  - using use SFAuthenticationSession (deprecated) instead of ASWebAuthenticationSession
  - secure mutual authentication using X.509v3 certificates
  - use of context to add security to authentication e.g. via IP or location data
  - set prefersEphemeralWebBrowserSession to true before calling start for a session
    on iOS
status: placeholder

---

