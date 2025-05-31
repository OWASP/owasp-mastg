---
title: MFA Implementation Best Practices Not Followed
id: MASWE-0028
alias: mfa-best-practices
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-AUTH-9]
  masvs-v2: [MASVS-AUTH-3]
  cwe: [287]

draft:
  description: e.g. not using auto-fill
  topics:
  - platform auto-fill from SMS
  - use of Sign-in with Apple
  - MFA best practices
  - (IEEE) unreliable channels such as voice mails and phone numbers must be avoided
  - is not enforced only locally but server-side
  - check if relies on static responses from the remote endpoint such as `"message":"Success"`
status: placeholder

---

