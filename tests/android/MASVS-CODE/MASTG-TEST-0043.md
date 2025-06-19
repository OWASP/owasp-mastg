---
masvs_v1_id:
- MSTG-CODE-8
masvs_v2_id:
- MASVS-CODE-4
platform: android
title: Memory Corruption Bugs
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

## Static Analysis

There are various items to look for:

- Are there native code parts? If so: check for the given issues in the general memory corruption section. Native code can easily be spotted given JNI-wrappers, .CPP/.H/.C files, NDK or other native frameworks.
- Is there Java code or Kotlin code? Look for Serialization/deserialization issues, such as described in [A brief history of Android deserialization vulnerabilities](https://securitylab.github.com/research/android-deserialization-vulnerabilities "android deserialization").

Note that there can be Memory leaks in Java/Kotlin code as well. Look for various items, such as: BroadcastReceivers which are not unregistered, static references to `Activity` or `View` classes, Singleton classes that have references to `Context`, Inner Class references, Anonymous Class references, AsyncTask references, Handler references, Threading done wrong, TimerTask references. For more details, please check:

- [9 ways to avoid memory leaks in Android](https://android.jlelse.eu/9-ways-to-avoid-memory-leaks-in-android-b6d81648e35e "9 ways to avoid memory leaks in Android")
- [Memory Leak Patterns in Android](https://android.jlelse.eu/memory-leak-patterns-in-android-4741a7fcb570 "Memory Leak Patterns in Android").

## Dynamic Analysis

There are various steps to take:

- In case of native code: use Valgrind or Mempatrol to analyze the memory usage and memory calls made by the code.
- In case of Java/Kotlin code, try to recompile the app and use it with [Squares leak canary](https://github.com/square/leakcanary "Leakcanary").
- Check with the [Memory Profiler from Android Studio](https://developer.android.com/studio/profile/memory-profiler "Memory profiler") for leakage.
- Check with the [Android Java Deserialization Vulnerability Tester](https://github.com/modzero/modjoda "Android Java Deserialization Vulnerability Tester"), for serialization vulnerabilities.
