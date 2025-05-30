---
title: Insecure Services
id: MASWE-0062
alias: insecure-services
platform: [android]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-PLATFORM-4]
  masvs-v2: [MASVS-PLATFORM-1, MASVS-STORAGE-2]

refs:
- https://developer.android.com/privacy-and-security/security-tips#Services
- https://developer.android.com/guide/topics/manifest/service-element
- https://developer.android.com/reference/android/app/Service
- https://developer.android.com/privacy-and-security/security-tips#binder-and-messenger-interfaces
draft:
  description: Unintentionally exported services, unrestricted permissions. Exposed
    binders e.g not using checkCallingPermission() to verify whether the caller has
    a required permission.
  topics:
  - Services
  - Exposed Binders via Exported Services
status: placeholder

---

