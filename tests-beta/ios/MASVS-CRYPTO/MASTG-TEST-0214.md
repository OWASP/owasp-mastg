---
title: Hardcoded Cryptographic Keys in Files
platform: ios
id: MASTG-TEST-0214
type: [static]
weakness: MASWE-0014
profiles: [L1, L2]
---

## Overview

Cryptographic keys may be embedded files such as configuration files or key files, certificate files, or other resource files bundled with the app, making them accessible to anyone who can extract the app's resources. Real-world cases include storing API keys, SSL/TLS private keys, or encryption keys within these files, which can lead to serious security vulnerabilities if the app is reverse-engineered.

- **Identified by File Extension**: Files with extensions such as `.key`, `.pem`, `.crt`, `.p12`, `.cer`, or `.der` often contain cryptographic keys or certificates.
- **Identified by PEM Markers**: Strings such as `-----BEGIN PRIVATE KEY-----`, `-----BEGIN CERTIFICATE-----`, or the byte sequence `0x2d 0x2d 0x2d 0x2d 0x2d` (representing `-----` in ASCII) within files indicate the presence of PEM-encoded keys or certificates.
- **Identified by Common Byte Patterns**: Binary files containing specific byte sequences that match known DER or PKCS#12 formats, such as `0x30 0x82` (indicating the start of a DER-encoded structure), can indicate the presence of cryptographic material.
- **Embedded in Property Lists or JSON Files**: Keys might be stored within `.plist` or `.json` configuration files, often encoded as Base64 strings.
- **Identified by Specific Strings**: Keywords such as `privateKey`, `key`, or `secret` within files or variable names can indicate embedded keys or sensitive data.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary looking for strings or sequences of bytes as indicated above.

## Observation

The output should include any instances where potential cryptographic keys are found hardcoded within the application's source code or binary.

## Evaluation

The test fails if hardcoded cryptographic keys are found within the source code or binary.

Ensure that any identified keys are indeed cryptographic keys used for security-relevant purposes. Avoid false positives by verifying the key's usage context (e.g., configuration settings or non-security-related constants might be misidentified as cryptographic keys).
