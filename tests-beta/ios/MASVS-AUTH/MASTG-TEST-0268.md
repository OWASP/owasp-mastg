---
platform: ios
title: References to APIs Allowing Fallback to Non-Biometric Authentication
id: MASTG-TEST-0268
apis: [kSecAccessControlUserPresence,SecAccessControlCreateWithFlags]
type: [static]
weakness: MASWE-0045
status: placeholder
note: This test statically checks if the app uses the Keychain API to access sensitive resources that should be protected by user authentication (e.g., tokens, keys) relying on the user's passcode instead of biometrics or allowing fallback to device passcode when biometric authentication fails.
---
