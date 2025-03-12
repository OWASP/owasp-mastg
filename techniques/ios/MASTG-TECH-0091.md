---
title: Injecting Libraries into an IPA Manually
platform: ios
---

This technique allows you to inject arbitrary libraries into an IPA file. After injecting the library, you'll have to install the modified IPA onto your device using @MASTG-TECH-0056.

This technique is useful when you want to add additional functionality or testing capabilities to an application. For example, you can inject the Frida Gadget into an IPA file to enable dynamic instrumentation of the application.

We'll use the Frida Gadget (`FridaGadget.dylib`) as an example but you can use this technique to inject any `.dylib` library you want.

## Obtaining the Library

In our example, the library is Frida Gadget, which can be downloaded from the [GitHub release page](https://github.com/frida/frida/releases) of the Frida project. Look for the latest release that matches your target platform and download the `frida-gadget-XX.YY.ZZ-ios-universal.dylib.xz` file.

Decompress the file using the `xz` tool and save it as `FridaGadget.dylib`:

```bash
xz -d <frida-gadget-XX.YY.ZZ-ios-universal.dylib.xz> -c > FridaGadget.dylib
```

## Adding the Library to the IPA

IPA files are ZIP archives, so you can use any ZIP tool to unpack the archive:

```bash
unzip UnCrackable-Level1.ipa
```

Next, copy the target library, in this case `FridaGadget.dylib`, into the `.app/Frameworks` directory (create the directory if it doesn't exist):

```bash
mkdir -p Payload/UnCrackable\ Level\ 1.app/Frameworks
cp FridaGadget.dylib Payload/UnCrackable\ Level\ 1.app/Frameworks/
```

Use @MASTG-TOOL-0059 to add a `load` command to the binary (`LC_LOAD_DYLIB`). The code below shows how this is done for the @MASTG-APP-0025:

```bash
optool install -c load -p "@executable_path/Frameworks/FridaGadget.dylib"  -t Payload/UnCrackable\ Level\ 1.app/UnCrackable\ Level\ 1

Found FAT Header
Found thin header...
Found thin header...
Inserting a LC_LOAD_DYLIB command for architecture: arm
Successfully inserted a LC_LOAD_DYLIB command for arm
Inserting a LC_LOAD_DYLIB command for architecture: arm64
Successfully inserted a LC_LOAD_DYLIB command for arm64
Writing executable to Payload/UnCrackable Level 1.app/UnCrackable Level 1...
```

After injecting the `load` command, you need to repackage the IPA:

```bash
zip -r patched.ipa Payload
```

To debug an iOS application obtained from the App Store, it needs to be re-signed with a development provisioning profile with the `get-task-allow` entitlement. How to re-sign an application is discussed in @MASTG-TECH-0079.
