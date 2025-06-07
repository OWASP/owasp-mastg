---
masvs_v1_id:
- MSTG-CODE-4
masvs_v2_id:
- MASVS-RESILIENCE-3
platform: android
title: Testing for Debugging Code and Verbose Error Logging
masvs_v1_levels:
- R
profiles: [R]
status: deprecated
covered_by: [MASTG-TEST-0263]
deprecation_note: New version available in MASTG V2
---

## Overview

## Static Analysis

To determine whether [`StrictMode`](https://developer.android.com/reference/android/os/StrictMode) is enabled, you can look for the `StrictMode.setThreadPolicy` or `StrictMode.setVmPolicy` methods. Most likely, they will be in the `onCreate` method.

The detection methods for the thread policy are:

- `detectDiskWrites()`
- `detectDiskReads()`
- `detectNetwork()`

The penalties for thread policy violation are:

- `penaltyLog()`: Logs a message to LogCat.
- `penaltyDeath()`: Crashes application, runs at the end of all enabled penalties.
- `penaltyDialog()`: Shows a dialog.

Have a look at the [best practices](https://code.tutsplus.com/tutorials/android-best-practices-strictmode--mobile-7581 "Android Best Practices: StrictMode") for using StrictMode.

## Dynamic Analysis

There are several ways of detecting `StrictMode`; the best choice depends on how the policies' roles are implemented. They include

- Logcat,
- a warning dialog,
- application crash.
