---
platform: android
title: Testing for App Permissions
id: MASTG-TEST-0x24
---

## Overview
Testing for app permissions in Android involves evaluating how an application requests, uses, and manages permissions to ensure they do not lead to security vulnerabilities. Proper permission management should protect sensitive user data and ensure that the application complies with Android's security model. The test aims to detect misconfigurations and unnecessary permissions.

## Steps

**Static analysis**
 1. Decompile the APK using tools like @MASTG-TOOL-0011.
 2. Examine the `AndroidManifest.xml` file for declared permissions by searching for `<uses-permission` tags.
 3. Review the permissions with the developer to identify the purpose of each permission set and remove unnecessary or dangerous permissions.

**Dynamic analysis**
 1. Permissions for installed applications can be retrieved with @MASTG-TOOL-0004.
 2. Use the @MASTG-TOOL-0004 with the following command :
`$  adb shell dumpsys package sg.vp.owasp_mobile.omtg_android`

  Please refer to this [permissions overview ↗](https://developer.android.com/guide/topics/permissions/overview#permission-groups "Table 1. Dangerous permissions and permission groups.") for descriptions of the listed permissions that are considered dangerous.

## Observation
The output shows the list of permissions used by the application.

## Evaluation
The test will fail if the correct permissions are used.