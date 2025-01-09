---
title: Launching a Repackaged App in Debug Mode
platform: ios
---

After the app has been installed on the device, it needs to be launched in debug mode. This is not the case when launching the app via springboard (the application will crash), but it is possible with various tools as explained in @MASTG-TECH-0056. When the application is running in debug mode, Frida can be injected into the process with name `Gadget`:

```bash
idevicedebug -d run sg.vp.UnCrackable1

# In a new terminal
frida -U -n Gadget
...
[iPhone::Gadget ]-> 
```

## Starting with iOS 17 and Xcode 15

Since Xcode 15 and iOS 17 the tool @MASTG-TOOL-0054 will [not work anymore to start an app in debug mode](https://github.com/ios-control/ios-deploy/issues/588).

A workaround to start the re-packaged app with the `FridaGadget.dylib` in debug mode (without using @MASTG-TOOL-0054) can be found [here](https://github.com/ios-control/ios-deploy/issues/588#issuecomment-1907913430).
