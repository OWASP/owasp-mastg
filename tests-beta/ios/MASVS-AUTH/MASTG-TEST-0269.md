---
platform: ios
title: Runtime Use Of APIs Allowing Fallback to Non-Biometric Authentication
id: MASTG-TEST-0269
apis: [kSecAccessControlUserPresence,SecAccessControlCreateWithFlags]
type: [dynamic]
weakness: MASWE-0045
status: draft
note: This test dynamically checks if the app uses the Keychain API to access sensitive resources that should be protected by user authentication (e.g., tokens, keys) relying on the user's passcode instead of biometrics or allowing fallback to device passcode when biometric authentication fails.
---
