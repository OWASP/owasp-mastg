---
title: Monitoring System Logs
platform: android
---

On Android you can easily inspect the log of system messages by using [`Logcat`](https://developer.android.com/tools/debugging/debugging-log.html "Debugging with Logcat"). There are two ways to execute Logcat:

- Logcat is part of _Dalvik Debug Monitor Server_ (DDMS) in Android Studio. If the app is running in debug mode, the log output will be shown in the Android Monitor on the Logcat tab. You can filter the app's log output by defining patterns in Logcat.

<img src="Images/Chapters/0x05b/log_output_Android_Studio.png" width="100%" />

- You can execute Logcat with adb to store the log output permanently:

```bash
adb logcat > logcat.log
```

With the following command you can specifically grep for the log output of the app in scope, just insert the package name. Of course your app needs to be running for `ps` to be able to get its PID.

```bash
adb logcat | grep "$(adb shell ps | grep <package-name> | awk '{print $2}')"
```
