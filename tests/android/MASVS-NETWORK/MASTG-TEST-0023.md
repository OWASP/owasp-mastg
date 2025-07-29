---
masvs_v1_id:
- MSTG-NETWORK-6
masvs_v2_id:
- MASVS-NETWORK-1
platform: android
title: Testing the Security Provider
masvs_v1_levels:
- L2
profiles: [L2]
---

## Overview

## Static Analysis

Applications based on the Android SDK should depend on GooglePlayServices. For example, in the gradle build file, you will find `compile 'com.google.android.gms:play-services-gcm:x.x.x'` in the dependencies block. You need to make sure that the `ProviderInstaller` class is called with either `installIfNeeded` or `installIfNeededAsync`. `ProviderInstaller` needs to be called by a component of the application as early as possible. Exceptions thrown by these methods should be caught and handled correctly. If the application cannot patch its @MASTG-KNOW-0011, it can either inform the API of its less secure state or restrict user actions (because all HTTPS traffic should be deemed riskier in this situation).

If you have access to the source code, check if the app handle any exceptions related to the security provider updates properly, and if it reports to the backend when the application is working with an unpatched security provider. The Android Developer documentation provides different examples showing [how to update the Security Provider to prevent SSL exploits](https://developer.android.com/privacy-and-security/security-gms-provider "Updating Your Security Provider to Protect Against SSL Exploits").

Lastly, make sure that NDK-based applications bind only to a recent and properly patched library that provides SSL/TLS functionality.

## Dynamic Analysis

When you have the source code:

1. Run the application in debug mode, then create a breakpoint where the app will first contact the endpoint(s).
2. Right click the highlighted code and select `Evaluate Expression`.
3. Type `Security.getProviders()` and press enter.
4. Check the providers and try to find `GmsCore_OpenSSL`, which should be the new top-listed provider.

When you do not have the source code:

1. Use @MASTG-TOOL-0001 to hook [`java.security.Security.getProviders()`](https://developer.android.com/reference/java/security/Security#getProviders()) or use a script @MASTG-TOOL-0032 like [@platix/get-android-security-provider-mstg-network-6](https://codeshare.frida.re/@platix/get-android-security-provider-mstg-network-6/).
2. Determine whether the first provider is `GmsCore_OpenSSL`.
