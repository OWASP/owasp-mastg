---
platform: ios
title: References to APIs for Event-Bound Biometric Authentication
id: MASTG-TEST-0266
apis: [LAContext.evaluatePolicy]
type: [static]
weakness: MASWE-0044
status: draft
note: This test statically checks if the app uses the LocalAuthentication API to access sensitive resources that should be protected by user authentication (e.g., tokens, keys) relying solely on the LocalAuthentication API for access control instead of using the Keychain API and requiring user presence.
---
