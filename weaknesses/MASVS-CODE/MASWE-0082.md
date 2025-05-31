---
title: Unsafe Handling of Data From Local Storage
id: MASWE-0082
alias: unsafe-local-storage
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v2: [MASVS-CODE-4]

refs:
- https://developer.android.com/topic/security/risks/path-traversal
- https://developer.android.com/topic/security/risks/zip-path-traversal
draft:
  description: When data is read from local storage, it should be treated as untrusted.
  topics:
  - Internal Storage
  - External Storage
  - UIDocumentPickerViewController used by the receiver app
status: placeholder

---

