---
platform: ios
title: References to APIs for Event-Bound Biometric Authentication
id: MASTG-TEST-0266
apis: [LAContext.evaluatePolicy]
type: [static]
weakness: MASWE-0044
profiles: [L2]
---

## Overview

This test checks if the app insecurely accesses sensitive resources that should be protected by user authentication (e.g., tokens, keys) relying solely** on the LocalAuthentication API for access control instead of using the Keychain API and requiring user presence.

The **LocalAuthentication** API (e.g., `LAContext`) provides user authentication (Touch ID, Face ID, device passcode), returning only a success or failure result. However, it **does not** securely store secrets or enforce any security. This makes it susceptible to logic manipulation (e.g., bypassing an `if authenticated { ... }` check).

In contrast, the **Keychain** API securely stores sensitive data, and can be configured with access control policies (e.g., require user presence such as biometrics) via `kSecAccessControl` flags. This ensures authentication is not just a one-time boolean, but part of a **secure data retrieval path (out-of-process)**, so bypassing authentication becomes significantly harder.

## Steps

1. Run a static analysis scan with @MASTG-TOOL-0073 to detect usage of `LAContext.evaluatePolicy`
2. Run a static analysis scan with @MASTG-TOOL-0073 to detect usage of Keychain APIs, especially `SecAccessControlCreateWithFlags` (which should go accompanied by other APIs such as `SecItemAdd` and `SecItemCopyMatching`).

## Observation

The analysis should output the locations where the `LAContext.evaluatePolicy` and Keychain APIs are used in the codebase (or the lack of their use).

## Evaluation

The test fails if for each sensitive data resource worth protecting:

- `LAContext.evaluatePolicy` is used explicitly.
- There are no calls to `SecAccessControlCreateWithFlags` requiring user presence with [any of the possible flags](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags).
