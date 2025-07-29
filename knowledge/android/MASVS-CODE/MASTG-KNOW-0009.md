---
masvs_category: MASVS-CODE
platform: android
title: StrictMode
---

StrictMode is a developer tool for detecting violations, e.g. accidental disk or network access to the app's main thread. It can also be used to check for good coding practices, such as implementing performant code.

Different policies can be set using the [ThreadPolicy Builder](https://developer.android.com/reference/android/os/StrictMode.ThreadPolicy.Builder) and the [VmPolicy Builder](https://developer.android.com/reference/android/os/StrictMode.VmPolicy.Builder).

Reaction to detected policy violations can be set using one or more of the `penalty*` methods. For example, `penaltyLog()` can be enabled to log any policy violation to the system log.

Below is an example of [`StrictMode`](https://developer.android.com/reference/android/os/StrictMode.html "StrictMode Class") with policies enabled for disk and network access to the main thread. If this is detected, a log message is written to the system log, and the app is forced to crash.

```java
public void onCreate() {
     if (BuildConfig.DEBUG) {
         StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder()
                 .detectDiskReads()
                 .detectDiskWrites()
                 .detectNetwork()   // or .detectAll() for all detectable problems
                 .penaltyLog()
                 .build());
         StrictMode.setVmPolicy(new StrictMode.VmPolicy.Builder()
                 .detectLeakedSqlLiteObjects()
                 .detectLeakedClosableObjects()
                 .penaltyLog()
                 .penaltyDeath()
                 .build());
     }
     super.onCreate();
 }
```

It is recommended to include the policy in the `if` statement with the `BuildConfig.DEBUG` condition to automatically enable StrictMode policies only for debug builds of your app.
