---
title: Repackaging Apps
platform: android
---

If you need to test on a non-jailbroken device you should learn how to repackage an app to enable dynamic testing on it.

Use a computer to perform all the steps indicated in the article ["Patching Android Applications"](https://github.com/sensepost/objection/wiki/Patching-Android-Applications) from the objection Wiki. Once you're done you'll be able to patch an APK by calling the objection command:

```bash
objection patchapk --source app-release.apk
```

The patched application then needs to be installed using adb.

> This repackaging method is enough for most use cases. For more advanced repackaging, refer to ["Repackaging & Re-Signing"](../../techniques/android/MASTG-TECH-0039.md "Repackaging & Re-Signing").
