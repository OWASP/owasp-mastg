---
title: Disassembling Code to Smali
platform: android
---

If you want to inspect the app's smali code (instead of Java), you can [open your APK in Android Studio](https://developer.android.com/studio/debug/apk-debugger "Debug pre-built APKs") by clicking **Profile or debug APK** from the "Welcome screen" (even if you don't intend to debug it you can take a look at the smali code).

Alternatively you can use @MASTG-TOOL-0011 to extract and disassemble resources directly from the APK archive and disassemble Java bytecode to smali. apktool allows you to reassemble the package, which is useful for @MASTG-TECH-0038 the app or applying changes to e.g. the Android Manifest.
