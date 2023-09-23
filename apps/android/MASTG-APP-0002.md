---
title: Android License Validator
platform: android
source: https://mas.owasp.org/crackmes/Android#android-license-validator
---

The Android License Validator is a crackme that implements a key validation function in native code, packaged as a standalone ELF executable for Android devices. Analyzing native code is often more challenging than Java, which is why critical business logic is frequently written this way.

While this sample application may not represent a real-world scenario, it serves as a valuable learning tool to grasp the basics of symbolic execution. These insights can be applied in practical situations, especially when dealing with Android apps that include obfuscated native libraries. In fact, obfuscated code is often put into native libraries specifically to make the process of de-obfuscation more challenging.

> By [Bernhard Mueller](https://github.com/muellerberndt "Bernhard Mueller")
