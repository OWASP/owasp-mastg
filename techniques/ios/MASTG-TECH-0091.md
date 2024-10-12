---
title: Patching automated
platform: ios
---

If you want to use Frida on non-jailbroken devices you'll need to include the `FridaGadget.dylib` into the IPA.

The tool @MASTG-TOOL-0038 will automate this task for you. Follow the instructions in the wiki for [patching iOS Applications](https://github.com/sensepost/objection/wiki/Patching-iOS-Applications).

Afterwards, you can [run the patched iOS app](https://github.com/sensepost/objection/wiki/Running-Patched-iOS-Applications).

If everything went well, the app should start in debugging mode with LLDB attached. Frida should then be able to attach to the app as well. You can verify this via the `frida-ps` command:

```bash
$ frida-ps -U
PID  Name
---  ------
499  Gadget
```

## Starting with iOS 17 and Xcode 15

Since Xcode 15 and iOS 17 the tool @MASTG-TOOL-0054 will [not work anymore to start an app in debug mode](https://github.com/ios-control/ios-deploy/issues/588).

A workaround to start the re-packaged app with the `FridaGadget.dylib` in debug mode (without using @MASTG-TOOL-0054) can be found [here](https://github.com/ios-control/ios-deploy/issues/588#issuecomment-1907913430).
