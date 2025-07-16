---
title: Dynamic Analysis on Non-Rooted Devices
platform: android
---

Non-rooted devices have the benefit of replicating an environment that the application is intended to run on.

Thanks to tools like @MASTG-TOOL-0038, you can patch the app in order to test it like if you were on a rooted device (but of course being jailed to that one app). To do that you have to perform one additional step: [patch the APK](https://github.com/sensepost/objection/wiki/Patching-Android-Applications#patching---patching-an-apk "patching - patching an APK") to include the [Frida gadget](https://www.frida.re/docs/gadget/ "Frida Gadget") library.

Now you can use objection to dynamically analyze the application on non-rooted devices.

The following commands summarize how to patch and start dynamic analysis using objection using the @MASTG-APP-0003 as an example:

```bash
# Download the Uncrackable APK
$ wget https://raw.githubusercontent.com/OWASP/mastg/master/Crackmes/Android/Level_01/UnCrackable-Level1.apk
# Patch the APK with the Frida Gadget
$ objection patchapk --source UnCrackable-Level1.apk
# Install the patched APK on the android phone
$ adb install UnCrackable-Level1.objection.apk
# After running the mobile phone, objection will detect the running frida-server through the APK
$ objection explore
```
