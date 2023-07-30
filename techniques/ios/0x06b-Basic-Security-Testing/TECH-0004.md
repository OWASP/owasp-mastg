---
title: Repackaging Apps
platform: ios
---

If you need to test on a non-jailbroken device you should learn how to repackage an app to enable dynamic testing on it.

Use a computer with macOS to perform all the steps indicated in the article ["Patching iOS Applications"](https://github.com/sensepost/objection/wiki/Patching-iOS-Applications) from the objection Wiki. Once you're done you'll be able to patch an IPA by calling the objection command:

```bash
objection patchipa --source my-app.ipa --codesign-signature 0C2E8200Dxxxx
```

Finally, the app needs to be installed (sideloaded) and run with debugging communication enabled. Perform the steps from the article ["Running Patched iOS Applications"](https://github.com/sensepost/objection/wiki/Running-Patched-iOS-Applications) from the objection Wiki (using ios-deploy).

```bash
ios-deploy --bundle Payload/my-app.app -W -d
```

Refer to ["Installing Apps"](#installing-apps) to learn about other installation methods. Some of them doesn't require you to have a macOS.

> This repackaging method is enough for most use cases. For more advanced repackaging, refer to ["iOS Tampering and Reverse Engineering - Patching, Repackaging and Re-Signing"](0x06c-Reverse-Engineering-and-Tampering.md#patching-repackaging-and-re-signing).
