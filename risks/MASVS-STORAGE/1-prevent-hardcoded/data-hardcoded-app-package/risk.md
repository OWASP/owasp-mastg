title: Sensitive Data Hardcoded in the App Package
alias: data-hardcoded-app-package
platform: [android, ios]
profiles: [L1, L2]
mappings:
  - android: 'https://developer.android.com/privacy-and-security/risks/hardcoded-cryptographic-secrets'
  - masvs-v2: [MASVS-STORAGE-1]

---

## Overview

Sensitive data, including cryptographic keys and authentication material, hardcoded in the app package, source code, or compiled binaries, poses significant security risks. This data can be easily extracted by attackers, compromising the security of the application and its users.

## Impact

Hardcoding sensitive information in the app can lead to a variety of security issues, including but not limited to:
- Unauthorized access to user data or services.
- Bypassing of authentication mechanisms.
- Compromise of cryptographic keys, leading to decryption of sensitive data.

## Modes of Introduction

Sensitive data can be hardcoded at various stages of app development, including:
- During initial development, as a shortcut for testing.
- In the configuration files or source code for convenience.
- Within third-party libraries or dependencies that may not follow best security practices.

## Mitigations

To mitigate the risks associated with hardcoded sensitive data, developers should:
- Use secure storage solutions provided by the platform, such as Android Keystore or iOS Keychain, to store sensitive information.
- Implement proper key management practices, including key rotation and using environment-specific keys.
- Avoid storing sensitive data within the app package or source code, and instead retrieve it securely from server-side services.
- Regularly audit the codebase and dependencies for hardcoded sensitive data.
