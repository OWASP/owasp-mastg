---
title: API Keys Hardcoded in the App Package
id: MASWE-0005
alias: api-keys-hardcoded-app-package
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v2: [MASVS-AUTH-1]
  mastg-v1: []
  cwe: [798]
  android-risks:
  - https://developer.android.com/privacy-and-security/risks/insecure-api-usage
status: new
refs:
- https://cloud.google.com/docs/authentication/api-keys#securing
- https://cloud.google.com/docs/authentication/api-keys#api_key_restrictions
---

## Overview

API keys hardcoded in the app package, source code, or compiled binaries, can be easily extracted through reverse engineering.

## Impact

Hardcoding API keys in the app can lead to a variety of security issues, including but not limited to:

- **Financial Loss**: Attackers can exploit the compromised hardcoded API keys to make unauthorized API calls and abuse services that are billed on a per-use basis (e.g., AI or ML API services), resulting in unexpected charges to the app owner.
- **Compromise of System Integrity and Business Operations**: Extracted API keys can give attackers unauthorized access to sensitive resources and services. This directly impacts developers and enterprises by compromising app integrity, privacy, and service continuity - potentially leading to disruptions such as Denial of Service (DoS) or service suspension due to policy violations. Such incidents can significantly impact the user experience, erode user trust, and negatively impact business reputation and operations.
- **Bypass Protection Mechanism**: Hardcoded API keys can make it easier to bypass app protection mechanisms. Attackers can use this to access restricted content, cheat in app functionality, or unlock features that are intended for purchase, impacting both revenue and user experience.

## Modes of Introduction

API keys can be hardcoded in several areas:

- **App Source Code**: directly embedded in the app source code.
- **App Assets**: included in files that are destined for the final deliverable app package (typically APK/IPA), such as configuration files, manifest files, and resource files.
- **Libraries**: configuration files or source code for third-party, first-party libraries or any other app dependencies.

## Mitigations

- Use a stateful API service that provides secure authentication, client validation, and session controls. Implement dynamic tokens that expire after a reasonably short time (e.g., 1 hour). This can help reduce the impact of key exposure. Also, ensure proper error handling and logging to detect and respond to unauthorized access attempts. Consider using OAuth 2.0 and security libraries like AppAuth to simplify secure OAuth flows.
- If a stateful API service is not viable, consider using a stateless API service with a middleware solution (sometimes known as API proxy or API Gateway). This involves proxying requests between the app and API endpoint. Use JSON Web Tokens (JWT) and JSON Web Signature (JWS) to store the vulnerable static key server-side rather than in the application (client). Implement secure key management practices and consider using a cloud key management service.
- If API keys must be hardcoded, be sure to configure them with the minimum required permissions to reduce the impact in case of exposure. Many services allow you to create keys with restricted access, which limits the operations that can be performed.
- Consider using a [Key Management Service](https://cloud.google.com/kms/docs/key-management-service) to get API keys on runtime after validating app integrity.
- Regularly audit the codebase and dependencies for hardcoded sensitive data (e.g. using tools such as [gitLeaks](https://github.com/gitleaks/gitleaks)).
- Use white-box cryptography techniques to encrypt API keys and sensitive data within the app, ensuring that the cryptographic algorithms and keys remain protected even if the app is reverse-engineered.
- While not foolproof, and **to be used as a last resort** when no other secure options are available, code and resource obfuscation and encryption can deter attackers by making it more difficult to analyze your app and discover hardcoded secrets. Avoid custom implementations and use well-established solutions such as RASP (Runtime Application Self-Protection) which can ensure that the API keys are only fully assembled in memory when necessary, keeping them obfuscated or split across different components otherwise. RASP can also dynamically retrieve and manage keys securely at runtime by integrating with secure key management solutions.
