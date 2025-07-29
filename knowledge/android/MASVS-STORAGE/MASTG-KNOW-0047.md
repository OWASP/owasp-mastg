---
masvs_category: MASVS-STORAGE
platform: android
title: Cryptographic Key Storage
---

To mitigate unauthorized use of keys on the Android device, Android KeyStore lets apps specify authorized uses of their keys when generating or importing the keys. Once made, authorizations cannot be changed.

Storing a Key - from most secure to least secure:

- the key is stored in hardware-backed Android KeyStore
- all keys are stored on server and are available after strong authentication
- the master key is stored on the server and used to encrypt other keys, which are stored in Android SharedPreferences
- the key is derived each time from a strong user provided passphrase with sufficient length and salt
- the key is stored in the software implementation of Android KeyStore
- the master key is stored in the software implementation of Android Keystore and used to encrypt other keys, which are stored in SharedPreferences
- [not recommended] all keys are stored in SharedPreferences
- [not recommended] hardcoded encryption keys in the source code
- [not recommended] predictable obfuscation function or key derivation function based on stable attributes
- [not recommended] stored generated keys in public places (like `/sdcard/`)

## Storing Keys Using Hardware-backed Android KeyStore

You can use the hardware-backed Android KeyStore (@MASTG-KNOW-0043) if the device is running Android 7.0 (API level 24) and above with available hardware component (Trusted Execution Environment (TEE) or a Secure Element (SE)). You can even verify that the keys are hardware-backed by using the guidelines provided for the secure implementation of Key Attestation (@MASTG-KNOW-0044). If a hardware component is not available and/or support for Android 6.0 (API level 23) and below is required, then you might want to store your keys on a remote server and make them available after authentication.

## Storing Keys on the Server

It is possible to securely store keys on a key management server, however the app needs to be online to decrypt the data. This might be a limitation for certain mobile app use cases and should be carefully thought through, as this becomes part of the architecture of the app and might highly impact usability.

## Deriving Keys from User Input

Deriving a key from a user provided passphrase is a common solution (depending on which Android API level you use), but it also impacts usability, might affect the attack surface and could introduce additional weaknesses.

Each time the application needs to perform a cryptographic operation, the user's passphrase is needed. Either the user is prompted for it every time, which isn't an ideal user experience, or the passphrase is kept in memory as long as the user is authenticated. Keeping the passphrase in memory is not a best-practice, as any cryptographic material must only be kept in memory while it is being used. Zeroing out a key is often a very challenging task as explained in ["Cleaning out Key Material"](#cleaning-out-key-material).

Additionally, consider that keys derived from a passphrase have their own weaknesses. For instance, the passwords or passphrases might be reused by the user or easy to guess. Please refer to the chapter ["Testing Cryptography"](0x04g-Testing-Cryptography.md#improper-key-derivation-functions) for more information.

## Cleaning out Key Material

The key material should be cleared out from memory as soon as it is not need anymore. There are certain limitations of reliably cleaning up secret data in languages with garbage collector (Java) and immutable strings (Swift, Objective-C, Kotlin). [Java Cryptography Architecture Reference Guide](https://docs.oracle.com/en/java/javase/16/security/java-cryptography-architecture-jca-reference-guide.html#GUID-C9F76AFB-6B20-45A7-B84F-96756C8A94B4 "Java Cryptography Architecture (JCA) Reference Guide") suggests using `char[]` instead of `String` for storing sensitive data, and nullify array after usage.

Note that some ciphers do not properly clean up their byte-arrays. For instance, the AES Cipher in BouncyCastle does not always clean up its latest working key, leaving some copies of the byte-array in memory. Next, BigInteger based keys (e.g. private keys) cannot be removed from the heap, nor zeroed out without additional effort. Clearing byte array can be achieved by writing a wrapper which implements [Destroyable](https://docs.oracle.com/javase/8/docs/api/javax/security/auth/Destroyable.html#destroy--).

## Storing Keys using Android KeyStore API

A more user-friendly and recommended way is to use the [Android KeyStore API](https://developer.android.com/reference/java/security/KeyStore.html "Android AndroidKeyStore API") system (itself or through KeyChain) to store key material. If it is possible, hardware-backed storage should be used. Otherwise, it should fallback to software implementation of Android Keystore. However, be aware that the `AndroidKeyStore` API has been changed significantly throughout versions of Android. In earlier versions, the `AndroidKeyStore` API only supported storing public/private key pairs (e.g., RSA). Symmetric key support has only been added since Android 6.0 (API level 23). As a result, a developer needs to handle the different Android API levels to securely store symmetric keys.

## Storing keys by encrypting them with other keys

In order to securely store symmetric keys on devices running on Android 5.1 (API level 22) or lower, we need to generate a public/private key pair. We encrypt the symmetric key using the public key and store the private key in the `AndroidKeyStore`. The encrypted symmetric key can be encoded using base64 and stored in the `SharedPreferences`. Whenever we need the symmetric key, the application retrieves the private key from the `AndroidKeyStore` and decrypts the symmetric key.

Envelope encryption, or key wrapping, is a similar approach that uses symmetric encryption to encapsulate key material. Data encryption keys (DEKs) can be encrypted with key encryption keys (KEKs) which are securely stored. Encrypted DEKs can be stored in `SharedPreferences` or written to files. When required, the application reads the KEK, then decrypts the DEK. Refer to [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#encrypting-stored-keys "OWASP Cryptographic Storage Cheat Sheet: Encrypting Stored Keys") to learn more about encrypting cryptographic keys.

Also, as the illustration of this approach, refer to the [`EncryptedSharedPreferences`](https://android.googlesource.com/platform/frameworks/support/+/8d4dee36b185eb647753338de4e161bebaeff24d/security/security-crypto/src/main/java/androidx/security/crypto/EncryptedSharedPreferences.java) from the **Jetpack security crypto library**.

!!! Warning

    The **Jetpack security crypto library**, including the `EncryptedFile` and  `EncryptedSharedPreferences` classes, has been [deprecated](https://developer.android.com/privacy-and-security/cryptography#jetpack_security_crypto_library). However, since an official replacement has not yet been released, we recommend using these classes until one is available.

## Insecure options to store keys

A less secure way of storing encryption keys, is in the SharedPreferences of Android. When [SharedPreferences](https://developer.android.com/reference/android/content/SharedPreferences.html "Android SharedPreference API") are used, the file is only readable by the application that created it. However, on rooted devices, any other application with root access can read the SharedPreferences file of other apps. This is not the case for the AndroidKeyStore, since AndroidKeyStore access is managed on the kernel level, which needs considerably more work and skill to bypass without the AndroidKeyStore clearing or destroying the keys.

The last three options are to use hardcoded encryption keys in the source code, having a predictable obfuscation function or key derivation function based on stable attributes, and storing generated keys in public places like `/sdcard/`. Hardcoded encryption keys are an issue, since this means every instance of the application uses the same encryption key. An attacker can reverse-engineer a local copy of the application to extract the cryptographic key, and use that key to decrypt any data which was encrypted by the application on any device.

Next, when you have a predictable key derivation function based on identifiers which are accessible to other applications, the attacker only needs to find the KDF and apply it to the device to find the key. Lastly, storing encryption keys publicly is also highly discouraged, as other applications can have permission to read the public partition and steal the keys.

## Data Encryption Using Third Party Libraries

There are several different open-source libraries that offer encryption capabilities specific to the Android platform.

- **[Java AES Crypto](https://github.com/tozny/java-aes-crypto "Java AES Crypto")** - A simple Android class for encrypting and decrypting strings.
- **[SQL Cipher](https://www.zetetic.net/sqlcipher/sqlcipher-for-android/ "SQL Cipher")** - SQLCipher is an open source extension to SQLite that provides transparent 256-bit AES encryption of database files.
- **[Themis](https://github.com/cossacklabs/themis "Themis cryptographic library")** - A cross-platform high-level cryptographic library that provides the same API across many platforms, for securing data during authentication, storage, messaging, etc.

> Please keep in mind that as long as the key is not stored in the KeyStore, it is always possible to easily retrieve the key on a rooted device and then decrypt the values you are trying to protect.
