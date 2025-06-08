---
title: Insecure Content Providers
id: MASWE-0064
alias: insecure-content-providers
platform: [android]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-STORAGE-6]
  masvs-v2: [MASVS-PLATFORM-1, MASVS-STORAGE-1]

refs:
- https://developer.android.com/topic/security/risks/content-resolver
- https://developer.android.com/reference/androidx/core/content/FileProvider
- https://developer.android.com/topic/security/risks/file-providers
- https://developer.android.com/privacy-and-security/security-tips#ContentProviders
draft:
  description: Unintentionally exported content providers, unprotected content providers,
    permission tags, protection level
  topics:
  - file-system based
  - FileProvider (Android)
  - database based
  - exposed
  - permission tags
  - protection level
status: placeholder

---

