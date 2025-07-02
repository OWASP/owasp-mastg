---
title: Insecure Deep Links
id: MASWE-0058
alias: insecure-deep-links
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-PLATFORM-3]
  masvs-v2: [MASVS-PLATFORM-1, MASVS-STORAGE-2, MASVS-CODE-4]

draft:
  description: e.g. use of URL Custom Schemes, unverified AppLinks/Universal Links,
    not validating URLs
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

