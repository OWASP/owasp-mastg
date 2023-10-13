---
masvs_v1_id:
- MSTG-STORAGE-3
masvs_v2_id:
- MASVS-STORAGE-2
platform: android
title: Leakage of Sensitive Data to Logs
profiles: ["L1", "L2"]
mappings:
  - cwe:
    - id: 200
      title: Exposure of Sensitive Information to an Unauthorized Actor
    - id: 359
      title: Exposure of Private Personal Information to an Unauthorized Actor
    - id: 497
      title: Exposure of Sensitive System Information to an Unauthorized Control Sphere
    - id: 532
      title: Insertion of Sensitive Information into Log File
  - owasp-masvs: [MASVS-STORAGE-2]
  - owasp-masvs-v1: [MSTG-STORAGE-3]
---

## Overview

Mobile apps may leak [sensitive data](MASTG-THEORY-0023.md "Sensitive Data") to [logs](MASTG-THEORY-0033.md "Logs"). This may include sensitive user data, such as passwords, credit card numbers, or other personally identifiable information (PII), as well as sensitive system data, such as cryptographic keys, session tokens, or other sensitive information.

This can typically occur in two ways:

- The application may log sensitive data to the system log, which can be accessed by other application on the device (in old OS versions or compromised devices or if they hold th appropriate permissions).
- The application may log sensitive data to a file in the application's data directory, which can be accessed by any application on the device if the device is rooted.

## Impact

Loss of confidentiality: An attacker with access to the device may be able to extract sensitive data from the logs. This may lead to further attacks, such as identity theft, or compromise of the application's backend.

## Mitigations

- Avoid logging sensitive data at all.
- Redact sensitive data in logs.
- Remove logging statements from production releases unless deemed necessary to the application or explicitly identified as safe, e.g. as a result of a security audit.
- Use log levels properly to ensure that sensitive data is not logged in production releases.
- Use flags to disable logging in production releases in case of an incident.
