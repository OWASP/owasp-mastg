---
title: objection for iOS
platform: ios
source: https://github.com/sensepost/objection
---

Objection offers several features specific to iOS. You can find the [full list of features](https://github.com/sensepost/objection/wiki/Features) on the project's page, but here are a few interesting ones:

- Repackage applications to include the Frida gadget
- Disable SSL pinning for popular methods
- Access application storage to download or upload files
- Execute custom Frida scripts
- Dump the Keychain
- Read plist files

All these tasks and more can be easily done by using the commands in objection's REPL. For example, you can obtain the classes used in an app, functions of classes or information about the bundles of an app by running:

```bash
$ ios hooking list classes
$ ios hooking list class_methods <ClassName>
$ ios bundles list_bundles
```

If you have a jailbroken device with frida-server installed, Objection can connect directly to the running Frida server to provide all its functionality without needing to repackage the application. However, it is not always possible to jailbreak the latest version of iOS, or you may have an application with advanced jailbreak detection mechanisms.

The ability to **perform advanced dynamic analysis on non-jailbroken devices** is one of the features that makes Objection incredibly useful. After following the repackaging process (@MASTG-TECH-0092) you will be able to run all the aforementioned commands which make it very easy to quickly analyze an application, or get around basic security controls.

## Using Objection on iOS

Starting up Objection depends on whether you've patched the IPA or whether you are using a jailbroken device running Frida-server. 
For running a patched IPA, the name Gadget should be specified using `-n Gadget`. Whereas when using frida-server, you need to specify which application you want to attach to or spawn.

```bash
# Connecting to a patched IPA
$ objection -n Gadget start

# Using Frida-server
# Using frida-ps to get the correct application name
$ frida-ps -Ua | grep -i Telegram
983  Telegram

# Connecting to the Telegram app through Frida-server
$ objection -n "Telegram" start
# Alternatively
$ objection -n 983 start

# Objection can also spawn the app through Frida-server using the application identifier
$ objection --spawn -n "org.telegram.messenger"
... [usb] resume
# Alternatively
$ objection -s -p -n "org.telegram.messenger
```

Once you are in the Objection REPL, you can execute any of the available commands. Below is an overview of some of the most useful ones:

```bash
# Show the different storage locations belonging to the app
$ env

# Disable popular ssl pinning methods
$ ios sslpinning disable

# Dump the Keychain
$ ios keychain dump

# Dump the Keychain, including access modifiers. The result will be written to the host in myfile.json
$ ios keychain dump --json <myfile.json>

# Show the content of a plist file
$ ios plist cat <myfile.plist>

```

More information on using the Objection REPL can be found on the [Objection Wiki](https://github.com/sensepost/objection/wiki/Using-objection "Using Objection")
