---
title: Missing Device Secure Lock Verification Implementation
id: MASWE-0008
alias: secured-device-detection-not-implemented
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-STORAGE-11]
  masvs-v2: [MASVS-RESILIENCE-1]

refs:
- https://developer.apple.com/documentation/localauthentication/logging_a_user_into_your_app_with_face_id_or_touch_id
- https://grep.app/search?q=isdevicesecure%28&filter[repo][0]=threema-ch/threema-android
- https://developer.android.com/reference/android/hardware/biometrics/BiometricManager#canAuthenticate(int)
draft:
  description: The app may not check for a secure device lock (e.g. device passcode) and may allow for unauthorized access to sensitive data. On iOS enforcing device lock security (i.e., ensuring a passcode is set) has an additional benefit which is that it is tightly coupled with data encryption, assuming the app leverages the correct data protection APIs.
  topics:
  - user set a device passcode via `isDeviceSecure()` on Android better than only ensuring that the secure screen lock is set via `KeyguardManager.isKeyguardSecure()`
  - before attempting to authenticate, test to make sure that you actually have the ability to do so by calling the `LAContext.canEvaluatePolicy(_:error:)` method on iOS
  - to make sure that biometrics can be used, verify that the `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` or the `kSecAttrAccessibleWhenPasscodeSet` protection class is set when the `SecAccessControlCreateWithFlags` method is called
status: placeholder

---
