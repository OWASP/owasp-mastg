---
title: Sensitive Data Stored With Insufficient Access Restrictions in Internal Locations
id: MASWE-0002
alias: data-insufficient-access-restrictions-internal
platform: [android]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-STORAGE-2]
  masvs-v2: [MASVS-STORAGE-2]

refs:
- https://developer.android.com/about/versions/nougat/android-7.0-changes#permfilesys
draft:
  description: Sensitive data may be stored in internal locations without ensuring
    exclusive app access (e.g. by using the wrong file permissions) and may be accessible
    to other apps.
  topics:
  - File permissions (Android)
status: draft

---

