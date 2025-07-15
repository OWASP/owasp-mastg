---
title: Insecure Parsing and Escaping
id: MASWE-0087
alias: insecure-parsing-escaping
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v2: [MASVS-CODE-4]
  cwe: [116, 611]

draft:
  description: e.g. XML External Entity (XXE) attacks, X509 certificate parsing, character escaping.
  topics:
  - The app does not properly escape or encode special characters when handling structured output formats (e.g., HTML, XML, JSON), which may lead to injection or rendering issues in downstream components (CWE-116).
  - The app parses XML input without restricting external entity resolution, allowing XML External Entity (XXE) attacks that can expose files, initiate SSRF, or disrupt app logic (CWE-611).
status: placeholder

---

