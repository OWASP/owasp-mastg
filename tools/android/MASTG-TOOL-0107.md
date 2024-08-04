---
title: JNITrace
platform: android
source: https://github.com/chame1eon/jnitrace
host:
- windows
- linux
- macOS
---

A Frida based tool to trace use of the JNI API in Android apps.

Native libraries contained within Android Apps often make use of the JNI API to utilize the Android Runtime. Tracking those calls through manual reverse engineering can be a slow and painful process. jnitrace works as a dynamic analysis tracing tool similar to frida-trace or strace but for the JNI.

<img src="https://i.ibb.co/ZJ04cBB/jnitrace-1.png" style="width: 80%; border-radius: 5px; margin: 2em" />
