---
title: Injecting Frida Gadget into an IPA Automatically
platform: ios
---

If you want to enable dynamic testing with Frida but don't have access to a jailbroken device, you can patch and repackage the target app to load the [Frida gadget](https://www.frida.re/docs/gadget/). This way, you can instrument the app and do everything you need to do for dynamic analysis (of course, you can't break out of the sandbox this way). However, this technique only works if the app binary isn't FairPlay-encrypted (i.e., obtained from the App Store).

On a jailbroken device, you can run `frida-server` which will take care of the injection for you, even in encrypted apps. However, on a non-jailbroken device we have to manually prepare the application. There are two approaches we can take:

- Install a debug version of the application and inject during application launch
- Repackage the application to already include the Frida Gadget

As an alternative to this automated approach, see @MASTG-TECH-0091.

You can inject Frida into an application using @MASTG-TOOL-0118 or @MASTG-TOOL-0038

## Frida

After following any of the techniques of @MASTG-TECH-0055, your application will be running with the `get-task-allow` entitlement, which means it can be debugged. This means that the `frida` CLI tool can spawn the application and inject the Frida Gadget automatically, even on non-jailbroken devices.

First, download the latest version of the Frida Gadget and move it to `/Users/<USER>/.cache/frida/gadget-ios.dylib`. Frida is released frequently, so find the latest version available on the [Github releases page](https://github.com/frida/frida/releases) or download via the command line after obtaining the latest URL:

```bash
wget https://github.com/frida/frida/releases/download/X.Y.Z/frida-gadget-X.Y.Z-ios-universal.dylib.gz
gzip -d frida-gadget-X.Y.Z-ios-universal.dylib.gz
mv frida-gadget-X.Y.Z-ios-universal.dylib /Users/MAS/.cache/frida/gadget-ios.dylib
```

Next, simply run `frida` as you would normally:

```bash
$ frida -U -f org.mas.myapp
     ____
    / _  |   Frida 16.5.9 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to iPhone (id=123456789)
Spawned `org.mas.myapp`. Resuming main thread!
[iPhone::org.mas.myapp]->
```

## Sideloadly

Sideloadly can be used to automatically inject libraries while repackaging and signing the app. To do so, click the `Advanced Options`, followed by `Inject dylibs/frameworks` and `+dylib/deb/bundle`:

<img src="Images/Techniques/0091-SideloadlyFrida.png" width="400px" />

After installation, you will not be able to launch the application from SpringBoard. However, you can launch the application in debug mode and attach Frida as explained in @MASTG-TECH-0055.

## Objection

Objection can inject the Frida Gadget into a given IPA file. Use a computer with macOS to perform all the steps indicated in the article ["Patching iOS Applications"](https://github.com/sensepost/objection/wiki/Patching-iOS-Applications) from the objection Wiki. Once you're done you'll be able to patch an IPA by calling the objection command:

```bash
objection patchipa --source my-app.ipa --codesign-signature 0C2E8200Dxxxx
```
