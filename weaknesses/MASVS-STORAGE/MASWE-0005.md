---
title: Sensitive Data Hardcoded in the App Package
id: MASWE-0005
alias: data-hardcoded-app-package
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v2: [MASVS-STORAGE-1]
  mastg-v1: []
  cwe: [259, 321, 798]
  android: https://developer.android.com/privacy-and-security/risks/hardcoded-cryptographic-secrets
status: new
---

## Overview

Sensitive data, including cryptographic keys and authentication material, hardcoded in the app package, source code, or compiled binaries, poses significant security risks, as attackers can easily extract this data through reverse engineering.

## Impact

Hardcoding sensitive information in the app can lead to a variety of security issues, including but not limited to:

- **Unauthorized Data Access**: The use of hardcoded credentials can lead to attackers impersonating legitimate users. This breach directly threatens user privacy by allowing unauthorized access to personal areas and accounts within the app, violating user trust.
- **Bypass Protection Mechanism**: Hardcoded data can facilitate bypassing app protection mechanisms. Attackers might exploit this to access restricted content, cheat in app functionalities, or unlock features intended for purchase, impacting both revenue and user experience.
- **Cryptographic Key Compromise**: Hardcoded cryptographic keys can result in the decryption of sensitive data intended to be securely transmitted or stored. This not only violates the confidentiality of the data, but also potentially exposes it to manipulation or theft.
- **Compromise of System Integrity and Business Operations**: Extracting hardcoded data, such as API keys, from the app can give attackers unauthorized access to sensitive resources and services. This directly impacts developers and enterprises by compromising app integrity, privacy, and service continuity - potentially leading to disruptions such as Denial of Service (DoS). Such breaches can significantly erode user confidence and have a detrimental effect on business reputation and operations.

## Modes of Introduction

Sensitive data can be hardcoded in several areas:

- **App Source Code**: directly embedded in the app source code.
- **App Assets**: included in files that are destined for the final deliverable app package (typically APK/IPA), such as configuration files, manifest files, and resource files.
- **Libraries**: configuration files or source code for third-party, first-party libraries or any other app dependencies.

## Mitigations

To mitigate the risks associated with hardcoded sensitive data, developers should:

- Use platform specific solutions to encrypt sensitive data, such as Android Keystore or iOS Keychain, before storing them locally.
- Implement proper key management practices, including key rotation and using environment-specific keys.
- Avoid storing sensitive data within the app package or source code, and instead securely retrieve it from server-side services that provide secure storage, access control, and auditing for sensitive data. For example, AWS Secrets Manager, Azure Key Vault, or Google Cloud Secret Manager are some popular managed secrets storage solutions. The app can securely retrieve the necessary secrets at runtime through secure, authenticated API calls.
- Where possible, generate cryptographic keys dynamically on the device, rather than using predefined keys, and ensure that they don't leave the platform-provided keystore. This approach reduces the risk associated with key transmission and storage.
- If data must be hardcoded, such as some API keys, be sure to configure them with the minimum required permissions to reduce the impact in case of exposure. Many services allow you to create keys with restricted access, which limits the operations that can be performed.
- Regularly audit the codebase and dependencies for hardcoded sensitive data (e.g. using tools such as [gitLeaks](https://github.com/gitleaks/gitleaks)).
- While not foolproof, and **to be used as a last resort** when no other secure options are available, code and resource obfuscation and encryption can deter attackers by making it more difficult to analyze your app and discover hard-coded secrets.
