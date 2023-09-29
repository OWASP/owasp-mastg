---
masvs_category: MASVS-CRYPTO
platform: android
---

# Android Cryptographic APIs

## Overview

In the chapter ["Mobile App Cryptography"](0x04g-Testing-Cryptography.md), we introduced general cryptography best practices and described typical issues that can occur when cryptography is used incorrectly. In this chapter, we'll go into more detail on Android's cryptography APIs. We'll show how to identify usage of those APIs in the source code and how to interpret cryptographic configurations. When reviewing code, make sure to compare the cryptographic parameters used with the current best practices, as linked in this guide.

We can identify key components of cryptography system on Android:

- [Security Provider](0x05e-Testing-Cryptography.md#security-provider)
- KeyStore - see the section [KeyStore](0x05d-Testing-Data-Storage.md#keystore) in the "Testing Data Storage" chapter
- KeyChain - see the section [KeyChain](0x05d-Testing-Data-Storage.md#keychain) in the "Testing Data Storage" chapter

Android cryptography APIs are based on the Java Cryptography Architecture (JCA). JCA separates the interfaces and implementation, making it possible to include several [security providers](https://developer.android.com/reference/java/security/Provider.html "Android Security Providers") that can implement sets of cryptographic algorithms. Most of the JCA interfaces and classes are defined in the `java.security.*` and `javax.crypto.*` packages. In addition, there are Android specific packages `android.security.*` and `android.security.keystore.*`.

KeyStore and KeyChain provide APIs for storing and using keys (behind the scene, KeyChain API uses KeyStore system). These systems allow to administer the full lifecycle of the cryptographic keys. Requirements and guidance for implementation of cryptographic key management can be found in [Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html "Key Management Cheat Sheet"). We can identify following phases:

- generating a key
- using a key
- storing a key
- archiving a key
- deleting a key

> Please note that storing of a key is analyzed in the chapter ["Testing Data Storage"](0x05d-Testing-Data-Storage.md).

These phases are managed by the Keystore/KeyChain system. However how the system works depends on how the application developer implemented it. For the analysis process you should focus on functions which are used by the application developer. You should identify and verify the following functions:

- [Key generation](0x05e-Testing-Cryptography.md#key-generation)
- [Random number generation](0x05e-Testing-Cryptography.md#random-number-generation)
- Key rotation

Apps that target modern API levels, went through the following changes:

- For Android 7.0 (API level 24) and above [the Android Developer blog shows that](https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html "Security provider Crypto deprecated in Android N"):
    - It is recommended to stop specifying a security provider. Instead, always use a [patched security provider](0x05e-Testing-Cryptography.md#updating-provider).
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

### General Recommendations

The following list of recommendations should be considered during app examination:

- You should ensure that the best practices outlined in the ["Cryptography for Mobile Apps"](0x04g-Testing-Cryptography.md) chapter are followed.
- You should ensure that security provider has the latest updates - [Updating security provider](https://developer.android.com/training/articles/security-gms-provider "Updating security provider").
- You should stop specifying a security provider and use the default implementation (AndroidOpenSSL, Conscrypt).
- You should stop using Crypto security provider and its `SHA1PRNG` as they are deprecated.
- You should specify a security provider only for the Android Keystore system.
- You should stop using Password-based encryption ciphers without IV.
- You should use KeyGenParameterSpec instead of KeyPairGeneratorSpec.

### Security Provider

Android relies on the `java.security.Provider` class to implement Java Security services. These providers are crucial to ensure secure network communications and secure other functionalities which depend on cryptography.  

The list of security providers included in Android varies between versions of Android and the OEM-specific builds. Some security provider implementations in older versions are now known to be less secure or vulnerable. Thus, Android applications should not only choose the correct algorithms and provide a good configuration, in some cases they should also pay attention to the strength of the implementations in the legacy security providers.

You can list the set of existing security providers using following code:

```java
StringBuilder builder = new StringBuilder();
for (Provider provider : Security.getProviders()) {
    builder.append("provider: ")
            .append(provider.getName())
            .append(" ")
            .append(provider.getVersion())
            .append("(")
            .append(provider.getInfo())
            .append(")\n");
}
String providers = builder.toString();
//now display the string on the screen or in the logs for debugging.
```

This is the output for Android 9 (API level 28) running in an emulator with Google Play APIs:

```default
provider: AndroidNSSP 1.0(Android Network Security Policy Provider)
provider: AndroidOpenSSL 1.0(Android's OpenSSL-backed security provider)
provider: CertPathProvider 1.0(Provider of CertPathBuilder and CertPathVerifier)
provider: AndroidKeyStoreBCWorkaround 1.0(Android KeyStore security provider to work around Bouncy Castle)
provider: BC 1.57(BouncyCastle Security Provider v1.57)
provider: HarmonyJSSE 1.0(Harmony JSSE Provider)
provider: AndroidKeyStore 1.0(Android KeyStore security provider)
```

#### Updating security provider

Keeping up-to-date and patched component is one of security principles. The same applies to `provider`. Application should check if used security provider is up-to-date and if not, [update it](https://developer.android.com/training/articles/security-gms-provider "Updating security provider").

#### Older Android versions

For some applications that support older versions of Android (e.g.: only used versions lower than Android 7.0 (API level 24)), bundling an up-to-date library may be the only option. Conscrypt library is a good choice in this situation to keep the cryptography consistent across the different API levels and avoid having to import [Bouncy Castle](https://www.bouncycastle.org/java.html "Bouncy Castle in Java") which is a heavier library.

[Conscrypt for Android](https://github.com/google/conscrypt#android "Conscrypt - A Java Security Provider") can be imported this way:

```groovy
dependencies {
  implementation 'org.conscrypt:conscrypt-android:last_version'
}
```

Next, the provider must be registered by calling:

```kotlin
Security.addProvider(Conscrypt.newProvider())
```

### Key Generation

The Android SDK allows you to specify how a key should be generated, and under which circumstances it can be used. Android 6.0 (API level 23) introduced the `KeyGenParameterSpec` class that can be used to ensure the correct key usage in the application. For example:

```java
String keyAlias = "MySecretKey";

KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(keyAlias,
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
        .setRandomizedEncryptionRequired(true)
        .build();

KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
        "AndroidKeyStore");
keyGenerator.init(keyGenParameterSpec);

SecretKey secretKey = keyGenerator.generateKey();
```

The `KeyGenParameterSpec` indicates that the key can be used for encryption and decryption, but not for other purposes, such as signing or verifying. It further specifies the block mode (CBC), padding (PKCS #7), and explicitly specifies that randomized encryption is required (this is the default). Next, we enter `AndroidKeyStore` as the name of the provider in the `KeyGenerator.getInstance` call to ensure that the keys are stored in the Android KeyStore.

GCM is another AES block mode that provides additional security benefits over other, older modes. In addition to being cryptographically more secure, it also provides authentication. When using CBC (and other modes), authentication would need to be performed separately, using HMACs (see the ["Tampering and Reverse Engineering on Android"](0x05c-Reverse-Engineering-and-Tampering.md) chapter). Note that GCM is the only mode of AES that [does not support padding](https://developer.android.com/training/articles/keystore.html#SupportedCiphers "Supported Ciphers in AndroidKeyStore").

Attempting to use the generated key in violation of the above spec would result in a security exception.

Here's an example of using that key to encrypt:

```java
String AES_MODE = KeyProperties.KEY_ALGORITHM_AES
        + "/" + KeyProperties.BLOCK_MODE_CBC
        + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7;
KeyStore AndroidKeyStore = AndroidKeyStore.getInstance("AndroidKeyStore");

// byte[] input
Key key = AndroidKeyStore.getKey(keyAlias, null);

Cipher cipher = Cipher.getInstance(AES_MODE);
cipher.init(Cipher.ENCRYPT_MODE, key);

byte[] encryptedBytes = cipher.doFinal(input);
byte[] iv = cipher.getIV();
// save both the IV and the encryptedBytes
```

Both the IV (initialization vector) and the encrypted bytes need to be stored; otherwise decryption is not possible.

Here's how that cipher text would be decrypted. The `input` is the encrypted byte array and `iv` is the initialization vector from the encryption step:

```java
// byte[] input
// byte[] iv
Key key = AndroidKeyStore.getKey(AES_KEY_ALIAS, null);

Cipher cipher = Cipher.getInstance(AES_MODE);
IvParameterSpec params = new IvParameterSpec(iv);
cipher.init(Cipher.DECRYPT_MODE, key, params);

byte[] result = cipher.doFinal(input);
```

Since the IV is randomly generated each time, it should be saved along with the cipher text (`encryptedBytes`) in order to decrypt it later.

Prior to Android 6.0 (API level 23), AES key generation was not supported. As a result, many implementations chose to use RSA and generated a public-private key pair for asymmetric encryption using `KeyPairGeneratorSpec` or used `SecureRandom` to generate AES keys.

Here's an example of `KeyPairGenerator` and `KeyPairGeneratorSpec` used to create the RSA key pair:

```java
Date startDate = Calendar.getInstance().getTime();
Calendar endCalendar = Calendar.getInstance();
endCalendar.add(Calendar.YEAR, 1);
Date endDate = endCalendar.getTime();
KeyPairGeneratorSpec keyPairGeneratorSpec = new KeyPairGeneratorSpec.Builder(context)
        .setAlias(RSA_KEY_ALIAS)
        .setKeySize(4096)
        .setSubject(new X500Principal("CN=" + RSA_KEY_ALIAS))
        .setSerialNumber(BigInteger.ONE)
        .setStartDate(startDate)
        .setEndDate(endDate)
        .build();

KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA",
        "AndroidKeyStore");
keyPairGenerator.initialize(keyPairGeneratorSpec);

KeyPair keyPair = keyPairGenerator.generateKeyPair();
```

This sample creates the RSA key pair with a key size of 4096-bit (i.e. modulus size). Elliptic Curve (EC) keys can also be generated in a similar way. However as of Android 11 (API level 30), [AndroidKeyStore does not support encryption or decryption with EC keys](https://developer.android.com/guide/topics/security/cryptography#SupportedCipher). They can only be used for signatures.

A symmetric encryption key can be generated from the passphrase by using the Password Based Key Derivation Function version 2 (PBKDF2). This cryptographic protocol is designed to generate cryptographic keys, which can be used for cryptography purpose. Input parameters for the algorithm are adjusted according to [weak key generation function](0x04g-Testing-Cryptography.md#weak-key-generation-functions) section. The code listing below illustrates how to generate a strong encryption key based on a password.

```java
public static SecretKey generateStrongAESKey(char[] password, int keyLength)
{
    //Initialize objects and variables for later use
    int iterationCount = 10000;
    int saltLength     = keyLength / 8;
    SecureRandom random = new SecureRandom();
    //Generate the salt
    byte[] salt = new byte[saltLength];
    random.nextBytes(salt);
    KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength);
    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();
    return new SecretKeySpec(keyBytes, "AES");
}
```

The above method requires a character array containing the password and the needed key length in bits, for instance a 128 or 256-bit AES key. We define an iteration count of 10,000 rounds which will be used by the PBKDF2 algorithm. Increasing the number of iterations significantly increases the workload for a brute-force attack on the password, however it can affect performance as more computational power is required for key derivation. We define the salt size equal to the key length divided by 8 in order to convert from bits to bytes and we use the `SecureRandom` class to randomly generate a salt. The salt needs to be kept constant to ensure the same encryption key is generated time after time for the same supplied password. Note that you can store the salt privately in `SharedPreferences`. It is recommended to exclude the salt from the Android backup mechanism to prevent synchronization in case of higher risk data.

> Note that if you take a rooted device or a patched (e.g. repackaged) application into account as a threat to the data, it might be better to encrypt the salt with a key that is placed in the `AndroidKeystore`. The Password-Based Encryption (PBE) key is generated using the recommended `PBKDF2WithHmacSHA1` algorithm, until Android 8.0 (API level 26). For higher API levels, it is best to use `PBKDF2withHmacSHA256`, which will end up with a longer hash value.

Note: there is a widespread false believe that the NDK should be used to hide cryptographic operations and hardcoded keys. However, using this mechanism is not effective. Attackers can still use tools to find the mechanism used and make dumps of the key in memory. Next, the control flow can be analyzed with e.g. radare2 and the keys extracted with the help of Frida or the combination of both: [r2frida](0x08a-Testing-Tools.md#r2frida) (see sections ["Disassembling Native Code"](0x05c-Reverse-Engineering-and-Tampering.md#disassembling-native-code "Disassembling Native Code"), ["Memory Dump"](0x05c-Reverse-Engineering-and-Tampering.md#memory-dump "Memory Dump") and ["In-Memory Search"](0x05c-Reverse-Engineering-and-Tampering.md#in-memory-search "In-Memory Search") in the chapter "Tampering and Reverse Engineering on Android" for more details). From Android 7.0 (API level 24) onward, it is not allowed to use private APIs, instead: public APIs need to be called, which further impacts the effectiveness of hiding it away as described in the [Android Developers Blog](https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html "Android changes for NDK developers")

### Random number generation

Cryptography requires secure pseudo random number generation (PRNG). Standard Java classes as `java.util.Random` do not provide sufficient randomness and in fact may make it possible for an attacker to guess the next value that will be generated, and use this guess to impersonate another user or access sensitive information.

In general, `SecureRandom` should be used. However, if the Android versions below Android 4.4 (API level 19) are supported, additional care needs to be taken in order to work around the bug in Android 4.1-4.3 (API level 16-18) versions that [failed to properly initialize the PRNG](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html "Some SecureRandom Thoughts").

Most developers should instantiate `SecureRandom` via the default constructor without any arguments. Other constructors are for more advanced uses and, if used incorrectly, can lead to decreased randomness and security. The PRNG provider backing `SecureRandom` uses the `SHA1PRNG` from `AndroidOpenSSL` (Conscrypt) provider.
