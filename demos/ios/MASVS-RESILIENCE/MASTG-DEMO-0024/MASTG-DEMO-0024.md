---
platform: ios
title: Uses of LAContext.canEvaluatePolicy with r2
id: MASTG-DEMO-0024
code: [swift]
test: MASTG-TEST-0248
---

### Sample

The following sample checks whether the device has a set passcode.

{{ MastgTest.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Run `run.sh`.

{{ isDevicePasscodeSet.r2 }}

{{ run.sh }}

### Observation

{{ output.asm }}

The output reveals the use of `LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)` in the app. However, it's not exactly the same in the output because the compiler transformed this function call into an Objective-C counterpart under the hood. Therefore, an equivalent Objective-C representation in the binary should look like `objc_msgSend(void *address, "canEvaluatePolicy:error:", LAPolicyDeviceOwnerAuthentication)`. By looking at the output we can find this pattern at line 11/12.

The third argument of `objc_msgSend(...)` is `LAPolicyDeviceOwnerAuthentication` because `w2` register at the time of the function invocation is set to `2` with a `mov` instruction at Line 9. `2` is an [enum](https://developer.apple.com/documentation/localauthentication/lapolicy?language=objc) representation of `LAPolicyDeviceOwnerAuthentication`.

### Evaluation

The test passes because the output shows references to passcode verification APIs.
