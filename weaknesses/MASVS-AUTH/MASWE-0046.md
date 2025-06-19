---
title: Crypto Keys Not Invalidated on New Biometric Enrollment
id: MASWE-0046
alias: crypto-keys-biometric-enrollment
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v2: [MASVS-AUTH-2, MASVS-CRYPTO-2]
  cwe: [287, 522]

draft:
  description: Biometric related crypto keys should be is invalidated by default whenever
    new biometric enrollments are added.
  topics:
  - Enabled by default on Android but can be disabled by calling `setInvalidatedByBiometricEnrollment(false)`
  - Disabled by default on iOS but can be enabled using `SecAccessControlCreateFlags.biometryCurrentSet`
    (prev. `touchIDCurrentSet`) when setting access control (since iOS 9). This invalidates
    keychain items when a fingerprint is added or removed. See kSecAccessControlTouchIDCurrentSet,
    biometryCurrentSet.
status: placeholder

---

