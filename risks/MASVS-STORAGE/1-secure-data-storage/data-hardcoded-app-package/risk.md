---
title: Sensitive Data Hardcoded in the App Package
platform: ["android", "ios"]
profiles: ["L1", "L2"]
mappings:
  - android: https://developer.android.com/privacy-and-security/risks/hardcoded-cryptographic-secrets
---

## Overview

Mobile apps may inadvertently include sensitive data, including cryptographic keys and authentication material, that is hardcoded within the app package. This sensitive data can be found in various areas, including the app package (APK/IPA), app source code, and compiled binary. Detecting and addressing such hardcoded data is crucial to prevent unauthorized access and potential security breaches.

## Modes of Introduction

Sensitive data can be hardcoded in the app package, source code, and compiled binary through various means, including:

- **App Package (APK/IPA):** Sensitive data may be embedded directly within the app package files, making it accessible to anyone who analyzes the package.
- **App Source Code:** Developers might include sensitive data in the source code, believing it is obscured or hidden, but it can still be extracted by attackers with access to the code.
- **Libraries (Libs):** Third-party libraries and components used by the app may contain hardcoded sensitive data, which can be a risk if not thoroughly reviewed and secured.

## Impact

The presence of hardcoded sensitive data in the app package can have significant security implications:

- **Unauthorized Access:** Attackers or malicious users who gain access to the hardcoded data can potentially access sensitive user information or backend systems which might lead to data breaches and potential legal consequences.

## Mitigations

To mitigate the risk of sensitive data being hardcoded in the app package, developers should take the following precautions:

- **Secure Coding Practices:** Adopt secure coding practices to avoid the inclusion of sensitive data in the source code. Use secure storage mechanisms for sensitive information, such as key vaults or secure storage APIs.
- **Code Review:** Conduct thorough code reviews to identify and remove any hardcoded sensitive data from the source code. Third-party libraries and components should also be scrutinized for hardcoded secrets.
- **Encryption:** Use secure encryption practices and avoid storing plaintext sensitive data within the app or its resources.
- **API Key Management:** Implement secure key management practices for API keys and authentication material, ensuring that they are not hardcoded but retrieved securely when needed.
- **Security Audits:** Regularly perform security audits and penetration testing to identify and address any instances of hardcoded sensitive data in the app package.
