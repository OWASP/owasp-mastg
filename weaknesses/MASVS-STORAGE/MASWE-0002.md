---
title: Sensitive Data Stored With Insufficient Access Restrictions in Internal Locations
id: MASWE-0002
alias: data-insufficient-access-restrictions-internal
platform: [android]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-STORAGE-2]
  masvs-v2: [MASVS-STORAGE-2]
  cwe: [200, 284, 732, 922]
  android-risks:
  - https://developer.android.com/privacy-and-security/risks/file-providers

refs:
- https://developer.android.com/about/versions/nougat/android-7.0-changes#permfilesys
- https://developer.android.com/privacy-and-security/security-tips#internal-storage
draft:
  description: Sensitive data may be stored in internal locations without ensuring
    exclusive app access (e.g. by using the wrong file permissions) and may be accessible
    to other apps.
  topics:
  - File permissions (Android)
  - improperly configured FileProvider (Android)
  - Avoid the deprecated MODE_WORLD_WRITEABLE and MODE_WORLD_READABLE modes for IPC files, see https://developer.android.com/privacy-and-security/security-tips#internal-storage. They don't provide the ability to limit data access to particular applications, and they don't provide any control of data format. If you want to share your data with other app processes, consider using a content provider instead, which offers read and write permissions to other apps and can make dynamic permission grants on a case-by-case basis.
  - Keychain items holding arbitrary data (excluding keys for this weakness) protected with weak protections such as kSecAttrAccessibleAlways, kSecAttrAccessibleAfterFirstUnlock,  kSecAttrAccessibleWhenUnlocked (iOS)

status: placeholder

---

