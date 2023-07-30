---
title: Repackaging Apps
platform: android
---

If you need to test on a non-jailbroken device you should learn how to repackage an app to enable dynamic testing on it.

Use a computer to perform all the steps indicated in the article ["Patching Android Applications"](https://github.com/sensepost/objection/wiki/Patching-Android-Applications) from the objection Wiki. Once you're done you'll be able to patch an APK by calling the objection command:

```bash
objection patchapk --source app-release.apk
```

The patched application then needs to be installed using adb, as explained in ["Installing Apps"](#installing-apps).

> This repackaging method is enough for most use cases. For more advanced repackaging, refer to ["Android Tampering and Reverse Engineering - Patching, Repackaging and Re-Signing"](0x05c-Reverse-Engineering-and-Tampering.md#patching-repackaging-and-re-signing).
