---
title: Device Attestation Not Implemented
id: MASWE-0100
alias: device-attestation
platform: [android, ios]
profiles: [R]
mappings:
  masvs-v1: [MSTG-RESILIENCE-10]
  masvs-v2: [MASVS-RESILIENCE-1]

refs:
- https://developer.android.com/google/play/integrity
- https://support.google.com/googleplay/android-developer/answer/11395166?hl=en
- https://www.youtube.com/watch?v=TyxL78e5Bag
- https://github.com/1nikolas/play-integrity-checker-app
- https://developer.apple.com/videos/play/wwdc2021/10244/ 
- https://developer.apple.com/documentation/devicecheck/preparing_to_use_the_app_attest_service 
- https://github.com/iansampson/AppAttest 
- https://github.com/firebase/firebase-ios-sdk/blob/master/FirebaseAppCheck/Sources/AppAttestProvider/DCAppAttestService+FIRAppAttestService.h 
- https://blog.restlesslabs.com/john/ios-app-attest
draft:
  description: e.g. Gooogle Play Integrity API, iOS DeviceCheck API
  topics:
  - detection in place
  - Effectiveness Assessment (e.g. bypassing the detection)
status: draft

---

