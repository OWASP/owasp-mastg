--- 
title: Obtaining App Permissions from Android Applications
platform: android 
---

In Android applications, permissions are acquired through different methods to access information and system functionalities, including the camera, location, or storage. The necessary permissions are specified in the `AndroidManifest.xml` file with `<uses-permission>` tags.

## Using the AndroidManifest

Extract the `AndroidManifest.xml` as explained in @MASTG-TECH-0117 and retrieve all [`<uses-permission>`](https://developer.android.com/guide/topics/manifest/uses-permission-element) elements.

## Using @MASTG-TOOL-0124

You can check the permissions of an APK file not only by manually reviewing the `AndroidManifest.xml` file but also by utilizing the Android Asset Packaging Tool (aapt), which is included in the build-tools folder of the Android SDK.

```bash
$ aapt d permissions org.owasp.mastestapp.apk
package: org.owasp.mastestapp
uses-permission: name='android.permission.INTERNET'
uses-permission: name='android.permission.CAMERA'
uses-permission: name='android.permission.WRITE_EXTERNAL_STORAGE'
uses-permission: name='android.permission.READ_CONTACTS'
uses-permission: name='android.permission.READ_EXTERNAL_STORAGE'
permission: org.owasp.mastestapp.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION
uses-permission: name='org.owasp.mastestapp.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION'
```

## Using @MASTG-TOOL-0004

Android's built-in debugging tool, ADB (Android Debug Bridge), provides a way to view permissions directly from a device or emulator.

```bash
$ adb shell dumpsys package org.owasp.mastestapp | grep permission
    declared permissions:
    requested permissions:
      android.permission.INTERNET
      android.permission.CAMERA
      android.permission.WRITE_EXTERNAL_STORAGE
      android.permission.READ_CONTACTS
      android.permission.READ_EXTERNAL_STORAGE
    install permissions:
      android.permission.INTERNET: granted=true
      runtime permissions:
        android.permission.READ_EXTERNAL_STORAGE: granted=false, flags=[ RESTRICTION_INSTALLER_EXEMPT]
        android.permission.CAMERA: granted=false
        android.permission.WRITE_EXTERNAL_STORAGE: granted=false, flags=[ RESTRICTION_INSTALLER_EXEMPT]
        android.permission.READ_CONTACTS: granted=false
```

Reference:

- To get a list of [dangerous permissions](https://android.googlesource.com/platform/frameworks/base/%2B/master/core/res/AndroidManifest.xml#886) in `AndroidManifest.xml`, look for permissions that have the attribute `android:protectionLevel="dangerous"`.
