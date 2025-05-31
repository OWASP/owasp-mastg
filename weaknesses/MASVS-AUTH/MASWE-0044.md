---
title: Biometric Authentication Can Be Bypassed
id: MASWE-0044
alias: event-bound-biometric-auth
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-AUTH-8]
  masvs-v2: [MASVS-AUTH-2]
  cwe: [287]

refs:
- https://developer.android.com/training/sign-in/biometric-auth#crypto
- https://labs.withsecure.com/publications/how-secure-is-your-android-keystore-authentication
- https://developer.apple.com/documentation/localauthentication/accessing_keychain_items_with_face_id_or_touch_id
- https://github.com/sensepost/objection/issues/136#issuecomment-419664574
- https://github.com/sensepost/objection/wiki/Understanding-the-iOS-Biometrics-Bypass
draft:
  description: It should be based on unlock platform KeyStore / crypto, use CryptoObject
  topics:
  - no use of CryptoObject
  - keychain items protected with access control flags such as kSecAccessControlTouchIDAny
    or kSecAccessControlTouchIDCurrentSet
status: placeholder

---

