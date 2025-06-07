---
masvs_v1_id:
- MSTG-PLATFORM-1
masvs_v2_id:
- MASVS-PLATFORM-1
platform: android
title: Testing for App Permissions
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: [MASTG-TEST-0254]
deprecation_note: New version available in MASTG V2
---

## Overview

When testing [app permissions](../../../Document/0x05h-Testing-Platform-Interaction.md#app-permissions "App Permissions") the goal is to try and reduce the amount of permissions used by your app to the absolute minimum. While going through each permission, remember that it is best practice first to try and [evaluate whether your app needs to use this permission](https://developer.android.com/training/permissions/evaluating) because many functionalities such as taking a photo can be done without, limiting the amount of access to sensitive data. If permissions are required you will then make sure that the request/response to access the permission is handled handled correctly.

## Static Analysis

### Android Permissions

Check permissions to make sure that the app really needs them and remove unnecessary permissions. For example, the `INTERNET` permission in the AndroidManifest.xml file is necessary for an Activity to load a web page into a WebView. Because a user can revoke an application's right to use a dangerous permission, the developer should check whether the application has the appropriate permission each time an action is performed that would require that permission.

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

Go through the permissions with the developer to identify the purpose of every permission set and remove unnecessary permissions.

Besides going through the AndroidManifest.xml file manually, you can also use the Android Asset Packaging tool (aapt) to examine the permissions of an APK file.

> aapt comes with the Android SDK within the build-tools folder. It requires an APK file as input. You may list the APKs in the device by running `adb shell pm list packages -f | grep -i <keyword>` as seen in @MASTG-TECH-0006.

```bash
$ aapt d permissions app-x86-debug.apk
package: sg.vp.owasp_mobile.omtg_android
uses-permission: name='android.permission.WRITE_EXTERNAL_STORAGE'
uses-permission: name='android.permission.INTERNET'
```

Alternatively you may obtain a more detailed list of permissions via adb and the dumpsys tool:

```bash
$ adb shell dumpsys package sg.vp.owasp_mobile.omtg_android | grep permission
    requested permissions:
      android.permission.WRITE_EXTERNAL_STORAGE
      android.permission.INTERNET
      android.permission.READ_EXTERNAL_STORAGE
    install permissions:
      android.permission.INTERNET: granted=true
      runtime permissions:
```

Please reference this [permissions overview](https://developer.android.com/guide/topics/permissions/overview#permission-groups "Table 1. Dangerous permissions and permission groups.") for descriptions of the listed permissions that are considered dangerous.

```default
READ_CALENDAR
WRITE_CALENDAR
READ_CALL_LOG
WRITE_CALL_LOG
PROCESS_OUTGOING_CALLS
CAMERA
READ_CONTACTS
WRITE_CONTACTS
GET_ACCOUNTS
ACCESS_FINE_LOCATION
ACCESS_COARSE_LOCATION
RECORD_AUDIO
READ_PHONE_STATE
READ_PHONE_NUMBERS
CALL_PHONE
ANSWER_PHONE_CALLS
ADD_VOICEMAIL
USE_SIP
BODY_SENSORS
SEND_SMS
RECEIVE_SMS
READ_SMS
RECEIVE_WAP_PUSH
RECEIVE_MMS
READ_EXTERNAL_STORAGE
WRITE_EXTERNAL_STORAGE
```

### Custom Permissions

Apart from enforcing custom permissions via the application manifest file, you can also check permissions programmatically. This is not recommended, however, because it is more error-prone and can be bypassed more easily with, e.g., runtime instrumentation. It is recommended that the `ContextCompat.checkSelfPermission` method is called to check if an activity has a specified permission. Whenever you see code like the following snippet, make sure that the same permissions are enforced in the manifest file.

```java
private static final String TAG = "LOG";
int canProcess = checkCallingOrSelfPermission("com.example.perm.READ_INCOMING_MSG");
if (canProcess != PERMISSION_GRANTED)
throw new SecurityException();
```

Or with `ContextCompat.checkSelfPermission` which compares it to the manifest file.

```java
if (ContextCompat.checkSelfPermission(secureActivity.this, Manifest.READ_INCOMING_MSG)
        != PackageManager.PERMISSION_GRANTED) {
            //!= stands for not equals PERMISSION_GRANTED
            Log.v(TAG, "Permission denied");
        }
```

### Requesting Permissions

If your application has permissions that need to be requested at runtime, the application must call the `requestPermissions` method in order to obtain them. The app passes the permissions needed and an integer request code you have specified to the user asynchronously, returning once the user chooses to accept or deny the request in the same thread. After the response is returned the same request code is passed to the app's callback method.

```java
private static final String TAG = "LOG";
// We start by checking the permission of the current Activity
if (ContextCompat.checkSelfPermission(secureActivity.this,
        Manifest.permission.WRITE_EXTERNAL_STORAGE)
        != PackageManager.PERMISSION_GRANTED) {

    // Permission is not granted
    // Should we show an explanation?
    if (ActivityCompat.shouldShowRequestPermissionRationale(secureActivity.this,
        //Gets whether you should show UI with rationale for requesting permission.
        //You should do this only if you do not have permission and the permission requested rationale is not communicated clearly to the user.
            Manifest.permission.WRITE_EXTERNAL_STORAGE)) {
        // Asynchronous thread waits for the users response.
        // After the user sees the explanation try requesting the permission again.
    } else {
        // Request a permission that doesn't need to be explained.
        ActivityCompat.requestPermissions(secureActivity.this,
                new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},
                MY_PERMISSIONS_REQUEST_WRITE_EXTERNAL_STORAGE);
        // MY_PERMISSIONS_REQUEST_WRITE_EXTERNAL_STORAGE will be the app-defined int constant.
        // The callback method gets the result of the request.
    }
} else {
    // Permission already granted debug message printed in terminal.
    Log.v(TAG, "Permission already granted.");
}
```

Please note that if you need to provide any information or explanation to the user it needs to be done before the call to `requestPermissions`, since the system dialog box can not be altered once called.

### Handling Responses to Permission Requests

Now your app has to override the system method `onRequestPermissionsResult` to see if the permission was granted. This method receives the `requestCode` integer as input parameter (which is the same request code that was created in `requestPermissions`).

The following callback method may be used for `WRITE_EXTERNAL_STORAGE`.

```java
@Override //Needed to override system method onRequestPermissionsResult()
public void onRequestPermissionsResult(int requestCode, //requestCode is what you specified in requestPermissions()
        String permissions[], int[] permissionResults) {
    switch (requestCode) {
        case MY_PERMISSIONS_WRITE_EXTERNAL_STORAGE: {
            if (grantResults.length > 0
                && permissionResults[0] == PackageManager.PERMISSION_GRANTED) {
                // 0 is a canceled request, if int array equals requestCode permission is granted.
            } else {
                // permission denied code goes here.
                Log.v(TAG, "Permission denied");
            }
            return;
        }
        // Other switch cases can be added here for multiple permission checks.
    }
}

```

Permissions should be explicitly requested for every needed permission, even if a similar permission from the same group has already been requested. For applications targeting Android 7.1 (API level 25) and older, Android will automatically give an application all the permissions from a permission group, if the user grants one of the requested permissions of that group. Starting with Android 8.0 (API level 26), permissions will still automatically be granted if a user has already granted a permission from the same permission group, but the application still needs to explicitly request the permission. In this case, the `onRequestPermissionsResult` handler will automatically be triggered without any user interaction.

For example if both `READ_EXTERNAL_STORAGE` and `WRITE_EXTERNAL_STORAGE` are listed in the Android Manifest but only permissions are granted for `READ_EXTERNAL_STORAGE`, then requesting `WRITE_EXTERNAL_STORAGE` will automatically have permissions without user interaction because they are in the same group and not explicitly requested.

### Permission Analysis

Always check whether the application is requesting permissions it actually requires. Make sure that no permissions are requested which are not related to the goal of the app, especially `DANGEROUS` and `SIGNATURE` permissions, since they can affect both the user and the application if mishandled. For instance, it should be suspicious if a single-player game app requires access to `android.permission.WRITE_SMS`.

When analyzing permissions, you should investigate the concrete use case scenarios of the app and always check if there are replacement APIs for any `DANGEROUS` permissions in use. A good example is the [SMS Retriever API](https://developers.google.com/identity/sms-retriever/overview) which streamlines the usage of SMS permissions when performing SMS-based user verification. By using this API an application does not have to declare `DANGEROUS` permissions which is a benefit to both the user and developers of the application, who doesn't have to submit the [Permissions Declaration Form](https://support.google.com/googleplay/android-developer/answer/9214102?hl=en).

## Dynamic Analysis

Permissions for installed applications can be retrieved with `adb`. The following extract demonstrates how to examine the permissions used by an application.

```bash
$ adb shell dumpsys package com.google.android.youtube
...
declared permissions:
  com.google.android.youtube.permission.C2D_MESSAGE: prot=signature, INSTALLED
requested permissions:
  android.permission.INTERNET
  android.permission.ACCESS_NETWORK_STATE
install permissions:
  com.google.android.c2dm.permission.RECEIVE: granted=true
  android.permission.USE_CREDENTIALS: granted=true
  com.google.android.providers.gsf.permission.READ_GSERVICES: granted=true
...
```

The output shows all permissions using the following categories:

- **declared permissions**: list of all _custom_ permissions.
- **requested and install permissions**: list of all install-time permissions including _normal_ and _signature_ permissions.
- **runtime permissions**: list of all _dangerous_ permissions.

When doing the dynamic analysis:

- [Evaluate](https://developer.android.com/training/permissions/evaluating) whether the app really needs the requested permissions. For instance: a single-player game that requires access to `android.permission.WRITE_SMS`, might not be a good idea.
- In many cases the app could opt for [alternatives to declaring permissions](https://developer.android.com/training/permissions/evaluating#alternatives), such as:
    - requesting the `ACCESS_COARSE_LOCATION` permission instead of `ACCESS_FINE_LOCATION`. Or even better not requesting the permission at all, and instead ask the user to enter a postal code.
    - invoking the `ACTION_IMAGE_CAPTURE` or `ACTION_VIDEO_CAPTURE` intent action instead of requesting the `CAMERA` permission.
    - using [Companion Device Pairing](https://developer.android.com/guide/topics/connectivity/companion-device-pairing) (Android 8.0 (API level 26) and higher) when pairing with a Bluetooth device instead of declaring the `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATIION`, or `BLUETOOTH_ADMIN` permissions.
- Use the [Privacy Dashboard](https://developer.android.com/training/permissions/explaining-access#privacy-dashboard) (Android 12 (API level 31) and higher) to verify how the app [explains access to sensitive information](https://developer.android.com/training/permissions/explaining-access).

To obtain detail about a specific permission you can refer to the [Android Documentation](https://developer.android.com/reference/android/Manifest.permission).
