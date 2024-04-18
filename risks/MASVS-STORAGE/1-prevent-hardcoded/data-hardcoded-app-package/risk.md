title: Sensitive Data Hardcoded in the App Package
alias: data-hardcoded-app-package
platform: [android, ios]
profiles: [L1, L2]
mappings:
  - masvs-v2: [MASVS-STORAGE-1]
  - mastg-v1: []
refs:
  - https://developer.android.com/privacy-and-security/risks/hardcoded-cryptographic-secrets
---

## Overview

Sensitive data, including cryptographic keys and authentication material, hardcoded in the app package, source code, or compiled binaries, poses significant security risks, as attackers can easily extract this data through reverse engineering.

## Impact

Hardcoding sensitive information in the app can lead to a variety of security issues, including but not limited to:
- Unauthorized access to user data or services.
- Bypassing of authentication mechanisms.
- Compromise of cryptographic keys, leading to decryption of sensitive data.

## Modes of Introduction

Sensitive data can be hardcoded in several areas:

- **App Source Code**: directly embedded in the app source code.
- **App Assets**: included in files that are destined for the final deliverable app package (typically APK/IPA), such as configuration files, manifest files, and resource files.
- **Libraries**: configuration files or source code for third-party, first-party libraries or any other app dependencies.

## Mitigations

To mitigate the risks associated with hardcoded sensitive data, developers should:
- Use secure storage solutions provided by the platform, such as Android Keystore or iOS Keychain, to store sensitive information.
- Implement proper key management practices, including key rotation and using environment-specific keys.
- Avoid storing sensitive data within the app package or source code, and instead retrieve it securely from server-side services.
- Regularly audit the codebase and dependencies for hardcoded sensitive data.
