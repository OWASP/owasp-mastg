---
title: objection for Android
platform: android
source: https://github.com/sensepost/objection
---

Objection offers several features specific to Android. You can find the [full list of features](https://github.com/sensepost/objection/wiki/Features) on the project's page, but here are a few interesting ones:

- Repackage applications to include the Frida gadget
- Disable SSL pinning for popular methods
- List the Activities, Services and Broadcast receivers
- Start Activities
- Detect implicit intents

If you have a rooted device with frida-server installed, Objection can connect directly to the running Frida server to provide all its functionality without needing to repackage the application. However, it is not always possible to root an Android device or the app may contain advanced RASP controls for root detection, so injecting a frida-gadget may be the easiest way to bypass those controls.

The ability to **perform advanced dynamic analysis on non-rooted devices** is one of the features that makes Objection incredibly useful. After following the repackaging process (@MASTG-TECH-0039) you will be able to run all the aforementioned commands which make it very easy to quickly analyze an application, or bypass basic security controls.

## Using Objection on Android

Starting up Objection depends on whether you've patched the APK or whether you are using a rooted device running Frida-server. For running a patched APK, either the foreground process `-F` or Gadget should be specified `-n Gadget`. Whereas when using frida-server, you need to specify which application you want to attach to or spawn.

```bash
# Connecting to a patched APK
objection -F explore

# Using Frida-server
# Find the correct name using frida-ps
$ frida-ps -Ua | grep -i telegram
30268  Telegram                               org.telegram.messenger

# Connecting to the Telegram app through Frida-server
$ objection --name "Telegram" start
# Alternatively
$ objection --name 30268 start

# Objection can also spawn the app through Frida-server using the application identifier
$ objection --spawn --name "org.telegram.messenger"
... [usb] resume
# Alternatively
$ objection --spawn --no-pause --name "org.telegram.messenger"
```

Once you are in the Objection REPL, you can execute any of the available commands. Below is an overview of some of the most useful ones:

```bash
# Show the different storage locations belonging to the app
$ env

# Disable popular ssl pinning methods
$ android sslpinning disable

# List items in the keystore
$ android keystore list

# Try to circumvent root detection
$ android root disable

```

More information on using the Objection REPL can be found on the [Objection Wiki](https://github.com/sensepost/objection/wiki/Using-objection "Using Objection")
