---
title: Injecting Frida Gadget into an IPA Automatically
platform: ios
---

If you want to enable dynamic testing with Frida but don't have access to a jailbroken device, you can patch and repackage the target app to load the [Frida gadget](https://www.frida.re/docs/gadget/). This way, you can instrument the app and do everything you need to do for dynamic analysis (of course, you can't break out of the sandbox this way). However, this technique only works if the app binary isn't FairPlay-encrypted (i.e., obtained from the App Store).

The easiest way to inject Frida into an installed application is by using frida-server. However, if this is not possible, the Frida Gadget can be injected into a decrypted IPA file.

As an alternative to this automated approach, see @MASTG-TECH-0091.

## @MASTG-TOOL-0118

Sideloadly can be used to automatically inject libraries while repackaging and signing the app. To do so, click the `Advanced Options`, followed by `Inject dylibs/frameworks` and `+dylib/deb/bundle`:

<img src="Images/Techniques/0091-SideloadlyFrida.png" width="400px" />

## @MASTG-TOOL-0038

Objection can inject the Frida Gadget into a given IPA file. Use a computer with macOS to perform all the steps indicated in the article ["Patching iOS Applications"](https://github.com/sensepost/objection/wiki/Patching-iOS-Applications) from the objection Wiki. Once you're done you'll be able to patch an IPA by calling the objection command:

```bash
objection patchipa --source my-app.ipa --codesign-signature 0C2E8200Dxxxx
```
