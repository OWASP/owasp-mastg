---
title: Injecting Frida Gadget into IPA Manually
platform: ios
---

The easiest way to inject Frida into an installed application is by using frida-server. However, if this is not possible, the Frida Gadget can be injected into a decrypted IPA file (see @MASTG-TECH-0054).

This technique describes a manual way of patching the IPA. Alternatively, see @MASTG-TECH-0091.

## Obtaining the Frida Gadget

The Frida Gadget can be downloaded from the [Github release page](https://github.com/frida/frida/releases). You are looking for the `frida-gadget-XX.YY.ZZ-ios-universal.dylib.xz` file. This file is compressed, so you need to decompress it using the `xz` tool. 

```bash
xz -d <frida-gadget-XX.YY.ZZ-ios-universal.dylib.xz> -c > FridaGadget.dylib
```

This will decompress the Frida Gadget and automatically save it to `FridaGadget.dylib`.

## Adding the Frida Gadget to the IPA

IPA files are ZIP archives, so you can use any ZIP tool to unpack the archive:

```bash
unzip UnCrackable-Level1.ipa
```

Next, copy the `FridaGadget.dylib` into the app directory and use @MASTG-TOOL-0059 to add a load command to the binary. The code below shows how this is done for the @MASTG-APP-0025:

```bash
unzip UnCrackable_Level1.ipa
mkdir -p Payload/UnCrackable\ Level\ 1.app/Frameworks
cp FridaGadget.dylib Payload/UnCrackable\ Level\ 1.app/Frameworks/
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

After injecting the load command, you need to recreate the IPA file:

```bash
zip -r patched.ipa Payload
```

Finally, install the IPA as described in @MASTG-TECH-0056.

## Launching the Repackaged App in Debug Mode

After the app has been installed on the device, it needs to be launched in debug mode. This is not the case when launching the app via springboard (the application will crash), but it is possible with various tools as explained in @MASTG-TECH-0056. When the application is running in debug mode, Frida can be injected into the process with name `Gadget`:

```bash
idevicedebug -d run sg.vp.UnCrackable1

# In a new terminal
frida -U -n Gadget
...
[iPhone::Gadget ]-> 
```