---
masvs_category: MASVS-CRYPTO
platform: android
---

# Android Cryptographic APIs

## Overview

In the chapter ["Mobile App Cryptography"](0x04g-Testing-Cryptography.md), we introduced general cryptography best practices and described typical issues that can occur when cryptography is used incorrectly. In this chapter, we'll go into more detail on Android's cryptography APIs. We'll show how to identify usage of those APIs in the source code and how to interpret cryptographic configurations. When reviewing code, make sure to compare the cryptographic parameters used with the current best practices, as linked in this guide.

We can identify key components of cryptography system on Android:

- @MASTG-KNOW-0011
- @MASTG-KNOW-0043
- @MASTG-KNOW-0048

Android cryptography APIs are based on the Java Cryptography Architecture (JCA). JCA separates the interfaces and implementation, making it possible to include several [security providers](https://developer.android.com/reference/java/security/Provider.html "Android Security Providers") that can implement sets of cryptographic algorithms. Most of the JCA interfaces and classes are defined in the `java.security.*` and `javax.crypto.*` packages. In addition, there are Android specific packages `android.security.*` and `android.security.keystore.*`.

KeyStore and KeyChain provide APIs for storing and using keys (behind the scene, KeyChain API uses KeyStore system). These systems allow to administer the full lifecycle of the cryptographic keys. Requirements and guidance for implementation of cryptographic key management can be found in [Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html "Key Management Cheat Sheet"). We can identify following phases:

- generating a key
- using a key
- storing a key
- archiving a key
- deleting a key

> Please note that storing of a key is analyzed in the chapter ["Testing Data Storage"](0x05d-Testing-Data-Storage.md).

These phases are managed by the Keystore/KeyChain system. However how the system works depends on how the application developer implemented it. For the analysis process you should focus on functions which are used by the application developer. You should identify and verify the following functions:

- @MASTG-KNOW-0012
- @MASTG-KNOW-0013
- Key rotation

Apps that target modern API levels, went through the following changes:

- For Android 7.0 (API level 24) and above [the Android Developer blog shows that](https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html "Security provider Crypto deprecated in Android N"):
    - It is recommended to stop specifying a security provider. Instead, always use a patched @MASTG-KNOW-0011.
    - The support for the `Crypto` provider has dropped and the provider is deprecated. The same applies to its `SHA1PRNG` for secure random.
- For Android 8.1 (API level 27) and above the [Developer Documentation](https://developer.android.com/about/versions/oreo/android-8.1 "Cryptography updates") shows that:
    - Conscrypt, known as `AndroidOpenSSL`, is preferred above using Bouncy Castle and it has new implementations: `AlgorithmParameters:GCM` , `KeyGenerator:AES`, `KeyGenerator:DESEDE`, `KeyGenerator:HMACMD5`, `KeyGenerator:HMACSHA1`, `KeyGenerator:HMACSHA224`, `KeyGenerator:HMACSHA256`, `KeyGenerator:HMACSHA384`, `KeyGenerator:HMACSHA512`, `SecretKeyFactory:DESEDE`, and `Signature:NONEWITHECDSA`.
    - You should not use the `IvParameterSpec.class` anymore for GCM, but use the `GCMParameterSpec.class` instead.
    - Sockets have changed from `OpenSSLSocketImpl` to `ConscryptFileDescriptorSocket`, and `ConscryptEngineSocket`.
    - `SSLSession` with null parameters give a `NullPointerException`.
    - You need to have large enough arrays as input bytes for generating a key otherwise, an `InvalidKeySpecException` is thrown.
    - If a Socket read is interrupted, you get a `SocketException`.
- For Android 9 (API level 28) and above the [Android Developer Blog](https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html "Cryptography Changes in Android P") shows even more changes:
    - You get a warning if you still specify a security provider using the `getInstance` method and you target any API below 28. If you target Android 9 (API level 28) or above, you get an error.
    - The `Crypto` security provider is now removed. Calling it will result in a `NoSuchProviderException`.
- For Android 10 (API level 29) the [Developer Documentation](https://developer.android.com/about/versions/10/behavior-changes-all#security "Security Changes in Android 10") lists all network security changes.

**General Recommendations:**

The following list of recommendations should be considered during app examination:

- You should ensure that the best practices outlined in the ["Cryptography for Mobile Apps"](0x04g-Testing-Cryptography.md) chapter are followed.
- You should ensure that security provider has the latest updates - [Updating security provider](https://developer.android.com/training/articles/security-gms-provider "Updating security provider").
- You should stop specifying a security provider and use the default implementation (AndroidOpenSSL, Conscrypt).
- You should stop using Crypto security provider and its `SHA1PRNG` as they are deprecated.
- You should specify a security provider only for the Android Keystore system.
- You should stop using Password-based encryption ciphers without IV.
- You should use KeyGenParameterSpec instead of KeyPairGeneratorSpec.
