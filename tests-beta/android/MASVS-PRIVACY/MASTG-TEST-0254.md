---
title: Dangerous App Permissions
platform: android
id: MASTG-TEST-0254
type: [static]
weakness: MASWE-0117
profiles: [P]
---

## Overview

In Android apps, permissions are acquired through different methods to access information and system functionalities, including the camera, location, or storage. The necessary permissions are specified in the `AndroidManifest.xml` file with `<uses-permission>` tags.

## Steps

There are multiple tools that can help in finding permissions in use by an app. Refer @MASTG-TECH-0118 to and use any of the mentioned tools.

1. Extract the `AndroidManifest.xml` file from the APK (see @MASTG-TECH-0117).
2. Obtain the list of declared permissions (see @MASTG-TECH-0126).

## Observation

The output shows the list of permissions declared by the app.

## Evaluation

The test fails if there are any dangerous permissions in the app.

Compare the list of declared permissions with the list of [dangerous permissions](https://android.googlesource.com/platform/frameworks/base/%2B/master/core/res/AndroidManifest.xml) defined by Android. You can find more details in the [Android documentation](https://developer.android.com/reference/android/Manifest.permission).

**Context Consideration**:

Context is essential when evaluating permissions. For example, an app that uses the camera to scan QR codes should have the `CAMERA` permission. However, if the app does not have a camera feature, the permission is unnecessary and should be removed.

Also, consider if there are any privacy-preserving alternatives to the permissions used by the app. For example, instead of using the `CAMERA` permission, the app could [use the device's built-in camera app](https://developer.android.com/privacy-and-security/minimize-permission-requests#take-photo) to capture photos or videos by invoking the `ACTION_IMAGE_CAPTURE` or `ACTION_VIDEO_CAPTURE` intent actions. This approach allows the app to access the camera functionality without directly requesting the `CAMERA` permission, thereby enhancing user privacy.
