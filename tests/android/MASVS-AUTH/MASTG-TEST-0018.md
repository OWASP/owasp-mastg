---
masvs_v1_id:
- MSTG-AUTH-8
masvs_v2_id:
- MASVS-AUTH-2
platform: android
title: Testing Biometric Authentication
masvs_v1_levels:
- L2
profiles: [L2]
---

## Overview

## Static Analysis

Note that there are quite some vendor/third party SDKs, which provide biometric support, but which have their own insecurities. Be very cautious when using third party SDKs to handle sensitive authentication logic.

## Dynamic Analysis

Please take a look at this detailed [blog article about the Android KeyStore and Biometric authentication](https://labs.withsecure.com/blog/how-secure-is-your-android-keystore-authentication "How Secure is your Android Keystore Authentication?"). This research includes two Frida scripts which can be used to test insecure implementations of biometric authentication and try to bypass them:

- [Fingerprint bypass](https://github.com/FSecureLABS/android-keystore-audit/blob/master/frida-scripts/fingerprint-bypass.js "Fingerprint Bypass"): This Frida script will bypass authentication when the `CryptoObject` is not used in the `authenticate` method of the `BiometricPrompt` class. The authentication implementation relies on the callback `onAuthenticationSucceded` being called.
- [Fingerprint bypass via exception handling](https://github.com/FSecureLABS/android-keystore-audit/blob/master/frida-scripts/fingerprint-bypass-via-exception-handling.js "Fingerprint bypass via exception handling"): This Frida script will attempt to bypass authentication when the `CryptoObject` is used, but used in an incorrect way. The detailed explanation can be found in the section "Crypto Object Exception Handling" in the blog post.
