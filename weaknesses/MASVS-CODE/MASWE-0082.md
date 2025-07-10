---
title: Unsafe Handling of Data From Local Storage
id: MASWE-0082
alias: unsafe-local-storage
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v2: [MASVS-CODE-4]
  cwe: [20, 22, 73, 349]

refs:
- https://developer.android.com/topic/security/risks/path-traversal
- https://developer.android.com/topic/security/risks/zip-path-traversal
draft:
  description: When data is read from local storage, it should be treated as untrusted.
  topics:
  - Internal Storage
  - External Storage
  - UIDocumentPickerViewController used by the receiver app
  - The app does not validate or sanitize input from local storage, which may lead to injection vulnerabilities when the data is interpreted or used in sensitive operations (CWE-20).
  - The app does not validate or sanitize file paths read from local storage, enabling potential path traversal attacks (CWE-22).
  - Paths to local files are influenced by attacker-controlled input, and their content can be modified (common in external storage or document pickers), leading to unintended file access or tampering (CWE-73).
  - The app processes data from local storage as if it were inherently trustworthy, without isolating or verifying it, allowing attackers to alter app state or behavior (CWE-349).
status: placeholder

---

