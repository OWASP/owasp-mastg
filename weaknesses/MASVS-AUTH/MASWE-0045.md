---
title: Fallback to Non-biometric Credentials Allowed for Sensitive Transactions
id: MASWE-0045
alias: no-biometric-fallback
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v2: [MASVS-AUTH-2]
  cwe: [288, 287]

refs:
- https://developer.android.com/training/sign-in/biometric-auth#allow-fallback
- https://developer.apple.com/documentation/localauthentication/logging_a_user_into_your_app_with_face_id_or_touch_id#3148834
- https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthenticationwithbiometrics/
draft:
  description: e.g. via DEVICE_CREDENTIAL on Android and LAPolicy.deviceOwnerAuthentication
    on iOS
  topics:
  - DEVICE_CREDENTIAL on Android
  - LAPolicy.deviceOwnerAuthentication on iOS
status: placeholder

---

