---
title: Corellium
platform: generic
source: https://corellium.com
---

Corellium is an iOS and Android device virtualization platform that allows users to create and manage virtual devices, perform dynamic analysis, and test applications in a controlled environment.

## Overview

Corellium offers a cloud-based solution that enables users to run virtualized iOS and Android devices. These virtual devices can be used for various purposes, including security testing, app development, and research. Corellium provides a web-based interface for managing the virtual devices, as well as APIs for automation and integration with other tools.

The Corellium GUI provides an app overview and app installer and many other features that are interesting for security testing, such as:

- [Built-in file browser](https://support.corellium.com/features/files/)
- [Built-in Frida server](https://support.corellium.com/features/frida/)
- [Snapshot management](https://support.corellium.com/features/snapshots)
- [Network monitor](https://support.corellium.com/features/network-monitor/)

## iOS emulation

Corellium is the only available commercial option for [iOS emulation](https://support.corellium.com/devices/ios). It is possible to launch all types of iOS devices with any supported iOS version. Each device can be jailbroken from the start, so even recent versions of iOS can be used to analyze applications.

While Corellium has some very powerful tools to analyze both applications and iOS itself, it does have a few important limitations:

- **No App Store**: The devices do not have the App Store, which means you cannot use a Corellium device to obtain a decrypted version of an IPA file.
- **No Apple Services**: Access to Apple services (including iMessage and push notifications) is unavailable.
- **No Camera / Cellular / NFC / Bluetooth**: Apps running on Corellium do not have access to these peripherals. But it does support [simulated SMS sending](https://support.corellium.com/features/messaging).

More on iOS testing can be found [here](https://support.corellium.com/features/apps/testing-ios-apps).

## Android emulation

[Android emulation](https://support.corellium.com/devices/android) is available in both the `user` and `userdebug` configuration and all images are rooted by default. Google Play and other Google Services are not installed by default, but Corellium does allow you to install them via an [OpenGApps](https://support.corellium.com/features/apps/opengapps) package. [Bluetooth](https://support.corellium.com/features/apps/bluetooth) is supported.

However, some features are not supported:

- **TrustZone**: It is not possible to access a Keymaster, or use PlayReady or Widevine.
- **SELinux in Permissive mode**: SELinux is set to permissive mode, which may be detected by applications. This is typically not the case for physical devices rooted with Magisk or KernelSU.

More on Android testing can be found [here](https://support.corellium.com/features/apps/debug-test-android-apps).
