---
title: Insecure Deep Links
id: MASWE-0058
alias: insecure-deep-links
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-PLATFORM-3]
  masvs-v2: [MASVS-PLATFORM-1, MASVS-STORAGE-2, MASVS-CODE-4]
  cwe: [939, 917]

draft:
  description: e.g. use of URL Custom Schemes, unverified AppLinks/Universal Links,
    not validating URLs. Deep Link parameters offers a wide range of possibilities. A malformed URI or parameter value, if not sanitized, may trigger an injection in different points of the application. For example, CWE-939 prevents the exploit of the URI checking the source and CWE-917 prevents the exploit of the URI checking the content.
  topics:
  - URL Custom Schemes
  - AppLinks
  - Universal Links
  - URL validation
  - Check for OS version. e.g. deep link are more secure after Android XX
refs:
- https://developer.apple.com/documentation/technotes/tn3155-debugging-universal-links
status: placeholder

---

