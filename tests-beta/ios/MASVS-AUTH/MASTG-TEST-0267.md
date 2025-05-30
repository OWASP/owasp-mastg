---
platform: ios
title: Runtime Use Of Event-Bound Biometric Authentication
id: MASTG-TEST-0267
apis: [LAContext.evaluatePolicy]
type: [dynamic]
weakness: MASWE-0044
best-practices: []
status: placeholder
note: This test dynamically checks if the app uses the LocalAuthentication API to access sensitive resources that should be protected by user authentication (e.g., tokens, keys) relying solely on the LocalAuthentication API for access control instead of using the Keychain API and requiring user presence.
---
