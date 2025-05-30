---
platform: ios
title: References to APIs Detecting Biometric Enrollment Changes
id: MASTG-TEST-0270
apis: [kSecAccessControlBiometryCurrentSet,SecAccessControlCreateWithFlags]
type: [static]
weakness: MASWE-0046
status: placeholder
note: This test statically checks if the app uses the Keychain API in a way that allows attackers to bypass biometric authentication by adding a new fingerprint or face representation via system settings.
---
