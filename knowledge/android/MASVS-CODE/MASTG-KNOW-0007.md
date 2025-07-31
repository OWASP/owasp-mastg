---
masvs_category: MASVS-CODE
platform: android
title: Debuggable Apps
---

Debugging is an essential process for developers to identify and fix errors or bugs in their Android app. By using a debugger, developers can select the device to debug their app on and set breakpoints in their Java, Kotlin, and C/C++ code. This allows them to analyze variables and evaluate expressions at runtime, which helps them to identify the root cause of many issues. By debugging their app, developers can improve the functionality and user experience of their app, ensuring that it runs smoothly without any errors or crashes.

Every debugger-enabled process runs an extra thread for handling JDWP protocol packets. This thread is started only for apps that have the `android:debuggable="true"` attribute in the [`Application` element](https://developer.android.com/guide/topics/manifest/application-element.html "Application element") within the Android Manifest.
