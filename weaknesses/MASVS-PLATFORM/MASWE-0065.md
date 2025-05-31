---
title: Sensitive Data Permanently Shared with Other Apps
id: MASWE-0065
alias: sensitive-data-shared-other-apps
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
  description: Provide clients one-time access to data. For example using URI permission
    grant flags and content provider permissions to display an app's PDF file in a
    separate PDF Viewer app.
  topics:
  - content providers
  - FLAG_GRANT_READ_URI_PERMISSION
  - FLAG_GRANT_WRITE_URI_PERMISSION
  - FLAG_GRANT_PERSISTABLE
  - content URIs
  - file URIs
status: placeholder

---

