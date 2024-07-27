---
title: Corellium
platform: generic
source: https://corellium.com
---

Corellium is an iOS and Android device virtualization platform that allows users to create and manage virtual devices, perform dynamic analysis, and test applications in a controlled environment.

## Overview

Corellium offers a cloud-based solution that enables users to run virtualized iOS and Android devices. These virtual devices can be used for various purposes, including security testing, app development, and research. Corellium provides a web-based interface for managing the virtual devices, as well as APIs for automation and integration with other tools.

## iOS emulation

Corellium is the only available commercial option for iOS emulation. It is possible to launch all types of iOS devices with any supported iOS version. Each device can be jailbroken from the start, so even recent versions of iOS can be used to analyze applications.

Through the GUI, Corellium provides multiple features that are interesting for security testing:

* Built-in file browser
* Built-in Frida server
* App overview and IPA installer
* Certificate-pinning bypass (may not always work)
* Snapshot management

While Corellium has some very powerfull tools to analyze both applications and iOS itself, it does have a few important limitations:

* **No App Store**: The devices do not have the App Store, which means you cannot use a Corellium device to obtain a decrypted version of an IPA file.
* **No Apple Services**: Access to Apple services (including iMessage and push notifications) is unavailable.
* **No Camera / Cellular / NFC / Bluetooth**: Apps running on Corellium do not have access to these peripherals.

## Android emulation

Android images are available in both the `user` and `userdebug` configuration and all images are rooted by default. Google Play and other Google Services are not installed by default, but Corellium does allow you to install them via an OpenGApps package.

Through the GUI, Corellium provides multiple features that are interesting for security testing:

* Built-in file browser
* Built-in Frida server
* App overview and IPA installer
* Certificate-pinning bypass (may not always work)
* Snapshot management

However, some features are not supported:

* **TrustZone**: It is not possible to access a Keymaster, or use PlayReady or WideFine.
* **SELinux in Permissive mode**: SELinux is set to permissive mode, which may be detected by applications. This is typically not the case for physical devices rooted with Magisk or KernelSU.