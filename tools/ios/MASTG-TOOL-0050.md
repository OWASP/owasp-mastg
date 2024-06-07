---
title: Frida-ios-dump
platform: ios
source: https://github.com/AloneMonkey/frida-ios-dump
---

[Frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump "Frida-ios-dump") is a Python script that helps you retrieve the decrypted version of an iOS app (IPA) from an iOS device. It supports both Python 2 and Python 3 and requires Frida running on your iOS device (jailbroken or not). This tool uses Frida's [Memory API](https://www.frida.re/docs/javascript-api/#memory "Frida Memory API") to dump the memory of the running app and recreate an IPA file. Because the code is extracted from memory, it is automatically decrypted.

## Alternatives

[Bagbak](https://github.com/ChiChou/bagbak "Bagbak") is a Node.js script that decrypts the entire application, including its extensions. It serves the same purpose as frida-ios-dump, but you might find it easier to set up and more convenient for regular use.