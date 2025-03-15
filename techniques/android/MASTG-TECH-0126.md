--- 
title: Obtaining App Permissions
platform: android 
---

Android permissions are declared in the `AndroidManifest.xml` file using the `<uses-permission>` tag. You can use multiple tools to view them.

## Using the AndroidManifest

Extract the `AndroidManifest.xml` as explained in @MASTG-TECH-0117 and retrieve all [`<uses-permission>`](https://developer.android.com/guide/topics/manifest/uses-permission-element) elements.

## Using @MASTG-TOOL-0124

`aapt` can be used to view the permissions requested by an application.

```bash
$ aapt d permissions org.owasp.mastestapp.apk
package: org.owasp.mastestapp
uses-permission: name='android.permission.INTERNET'
uses-permission: name='android.permission.CAMERA'
uses-permission: name='android.permission.WRITE_EXTERNAL_STORAGE'
uses-permission: name='android.permission.READ_CONTACTS'
uses-permission: name='android.permission.READ_EXTERNAL_STORAGE'
uses-permission: name='org.owasp.mastestapp.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION'
```

## Using @MASTG-TOOL-0004

`adb` can be used to view the permissions requested by an application. It also shows the status of the permissions (granted or denied) at runtime.

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
