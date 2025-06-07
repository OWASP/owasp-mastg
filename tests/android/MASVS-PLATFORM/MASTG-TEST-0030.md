---
masvs_v1_id:
- MSTG-PLATFORM-4
masvs_v2_id:
- MASVS-PLATFORM-1
platform: android
title: Testing for Vulnerable Implementation of PendingIntent
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

When testing [Pending Intents](../../../Document/0x05h-Testing-Platform-Interaction.md#pending-intents) you must ensure that they are immutable and that the app explicitly specifies the exact package, action, and component that will receive the base intent.

## Static Analysis

To identify vulnerable implementations, static analysis can be performed by looking for API calls used for obtaining a `PendingIntent`. Such APIs are listed below:

```java
PendingIntent getActivity(Context, int, Intent, int)
PendingIntent getActivity(Context, int, Intent, int, Bundle)
PendingIntent getActivities(Context, int, Intent, int, Bundle)
PendingIntent getActivities(Context, int, Intent, int)
PendingIntent getForegroundService(Context, int, Intent, int)
PendingIntent getService(Context, int, Intent, int)
```

Once any of the above function is spotted, check the implementation of the base intent and the `PendingIntent` for the security pitfalls listed in the [Pending Intents](../../../Document/0x05h-Testing-Platform-Interaction.md#pending-intents) section.

For example, in [A-156959408](https://android.googlesource.com/platform/frameworks/base/+/6ae2bd0e59636254c32896f7f01379d1d704f42d "A-156959408")(CVE-2020-0389), the base intent is implicit and also the `PendingIntent` is mutable, thus making it exploitable.

```java
private Notification createSaveNotification(Uri uri) {
    Intent viewIntent = new Intent(Intent.ACTION_VIEW)
            .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_GRANT_READ_URI_PERMISSION)
            .setDataAndType(uri, "video/mp4"); //Implicit Intent

//... skip ...


Notification.Builder builder = new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_android)
                .setContentTitle(getResources().getString(R.string.screenrecord_name))
                .setContentText(getResources().getString(R.string.screenrecord_save_message))
                .setContentIntent(PendingIntent.getActivity(
                        this,
                        REQUEST_CODE,
                        viewIntent,
                        Intent.FLAG_GRANT_READ_URI_PERMISSION))     // Mutable PendingIntent.
                .addAction(shareAction)
                .addAction(deleteAction)
                .setAutoCancel(true);

```

## Dynamic Analysis

Frida can be used to hook the APIs used to get a `PendingIntent`. This information can be used to determine the code location of the call, which can be further used to perform static analysis as described above.

Here's an example of such a Frida script that can be used to hook the `PendingIntent.getActivity` function:

```javascript
var pendingIntent = Java.use('android.app.PendingIntent');

var getActivity_1 = pendingIntent.getActivity.overload("android.content.Context", "int", "android.content.Intent", "int");

getActivity_1.implementation = function(context, requestCode, intent, flags){
    console.log("[*] Calling PendingIntent.getActivity("+intent.getAction()+")");
    console.log("\t[-] Base Intent toString: " + intent.toString());
    console.log("\t[-] Base Intent getExtras: " + intent.getExtras());
    console.log("\t[-] Base Intent getFlags: " + intent.getFlags());
    return this.getActivity(context, requestCode, intent, flags);
}
```

This approach can be helpful when dealing with applications with large code bases, where determining the control flow can sometimes be tricky.
