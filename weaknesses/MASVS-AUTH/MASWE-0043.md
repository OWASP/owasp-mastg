---
title: App Custom PIN Not Bound to Platform KeyStore
id: MASWE-0043
alias: custom-pin-keystore
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v2: [MASVS-AUTH-2, MASVS-CRYPTO-2]
  cwe: [922, 326, 312]

draft:
  description: It's better to use the OS Local Auth / bind to a key stored in the platform KeyStore. Consider new title App Custom Password Not Bound to Platform KeyStore where password could be password or PIN.
  topics:
  - use the OS Local Auth
  - binding to keys stored in the platform KeyStore
  - https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/applicationpassword
status: placeholder

---

