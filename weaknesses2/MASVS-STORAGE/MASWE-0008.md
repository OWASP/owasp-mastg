---
title: Device Access Security Policy Not Enforced
id: MASWE-0008
alias: device-access-policy-not-enforced
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-STORAGE-11]
  masvs-v2: [MASVS-STORAGE-1, MASVS-AUTH-2]

refs:
- https://developer.apple.com/documentation/localauthentication/logging_a_user_into_your_app_with_face_id_or_touch_id
- https://grep.app/search?q=isdevicesecure%28&filter[repo][0]=threema-ch/threema-android
draft:
  description: The app may not enforce device access security policy (e.g. device
    passcode) and may allow for unauthorized access to sensitive data.
  topics:
  - user set a device passcode via isDeviceSecure() on Android better than only ensuring
    that the lock screen is set via `KeyguardManager.isKeyguardSecure()`
  - before attempting to authenticate, test to make sure that you actually have the
    ability to do so by calling the LAContext.canEvaluatePolicy(_:error:) method on
    iOS
  - to make sure that biometrics can be used, verify that the `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`
    or the `kSecAttrAccessibleWhenPasscodeSet` protection class is set when the `SecAccessControlCreateWithFlags`
    method is called
status: draft

---

