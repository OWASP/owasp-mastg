--- 
title: Obtaining App Permissions from Android Applications
platform: android 
---

Obtaining App Permissions from Android Applications. There are several ways to obtain permissions from an Android application. Below are the tools and techniques commonly used:

## Using @MASTG-TOOL-0018

You can use Jadx or Jadx-GUI to decompile APK files and access the AndroidManifest.xml file. This allows you to view the permissions declared in the application and inspect their usage in the code. Jadx is particularly useful for static analysis as it can also decompile application code, helping identify how permissions are utilized within the app logic.

Steps:

1. Open the APK file in Jadx or Jadx-GUI.
2. Navigate to the AndroidManifest.xml file to view the declared permissions.

## Using @MASTG-TOOL-0011

You can also decompile an APK using APKTool to extract the AndroidManifest.xml file.

```bash
apktool d org.owasp.mastestapp.apk
```

This command decompresses the APK and extracts all resources, including the manifest file, which lists the permissions.
APKTool is useful for detailed reverse engineering and modifying app resources if needed.

## Using @MASTG-TOOL-0124

Besides manually inspecting the AndroidManifest.xml file, you can use the Android Asset Packaging Tool (AAPT) to examine the permissions of an APK file. AAPT is included in the Android SDK within the build-tools folder.

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

This command lists all the permissions requested by the app in a concise format, saving time compared to manual inspection.
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

This command retrieves the permissions declared in the app, as well as runtime-granted permissions if the app is installed on a device. It is especially useful during dynamic analysis or when testing an app in a live environment.

## Using @MASTG-TOOL-0031

Apart from enforcing custom permissions via the application manifest file, you can also check permissions using dynamic instrumentation. This is not recommended, however, because it is more error-prone and can be bypassed more easily with, e.g., runtime instrumentation. It is recommended that the ContextCompat.checkSelfPermission method is called to check if an activity has a specified permission. You can use this frida script from the [frida codeshare](https://codeshare.frida.re/@ScreaMy7/hookpermissions/) to check for runtime permissions.

```bash
frida -U -l hookpermissions.js -f org.owasp.mastestapp
```

Additional Notes:

- Permission Scope: Pay attention to runtime permissions (introduced in Android 6.0) versus manifest-declared permissions. Some permissions require explicit user approval at runtime.

- Refer to this [listed permissions](https://stackoverflow.com/questions/36936914/list-of-android-permissions-normal-permissions-and-dangerous-permissions-in-api) that are considered dangerous.
