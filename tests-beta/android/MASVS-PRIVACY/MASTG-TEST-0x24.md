---
platform: android
title: Dangerous App Permissions
id: MASTG-TEST-0x24
weakness: MASWE-0117
---

## Overview

In Android applications, permissions are acquired through different methods to access information and system functionalities, including the camera, location, or storage. The necessary permissions are specified in the `AndroidManifest.xml` file with `<uses-permission>` tags.

## Steps

There are multiple tools that can help in finding permissions in use by an application. Refer @MASTG-TECH-0118 to and use any of the mentioned tools.

1. Run a static analysis tool such as `@MASTG-TOOL-0110` on the `AndroidManifest.xml` file. Alternatively, you can refer to `@MASTG-TECH-0118` to get a list of permissions used by the applications and then identify any dangerous permissions.

## Observation

The output shows the list of dangerous permissions used by the application.

## Evaluation

- The test fails if there are any dangerous permissions in the app.
- To obtain a list of [dangerous permissions](https://android.googlesource.com/platform/frameworks/base/%2B/master/core/res/AndroidManifest.xml#886) in `AndroidManifest.xml`, examine the permission attribute `android:protectionLevel="dangerous"`.

**Context Consideration**:

To reduce false positives, dangerous permissions in Android applications should be carefully evaluated. Permissions should only be requested if they are essential to the functionality of the application, and users must be informed of their purpose before access is granted.
