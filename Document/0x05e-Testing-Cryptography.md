# Android Cryptographic APIs

## Overview

In the chapter ["Mobile App Cryptography"](0x04g-Testing-Cryptography.md), we introduced general cryptography best practices and described typical issues that can occur when cryptography is used incorrectly. In this chapter, we'll go into more detail on Android's cryptography APIs. We'll show how to identify usage of those APIs in the source code and how to interpret cryptographic configurations. When reviewing code, make sure to compare the cryptographic parameters used with the current best practices linked from this guide.

We can identify key components of cryptography system in Android:

- [Security Provider](0x05e-Testing-Cryptography.md#security-provider)
- KeyStore - see the section [KeyStore](0x05d-Testing-Data-Storage.md#keystore) in the chapter "Testing Data Storage"
- KeyChain - see the section [KeyChain](0x05d-Testing-Data-Storage.md#keychain) in the chapter "Testing Data Storage"

Android cryptography APIs are based on the Java Cryptography Architecture (JCA). JCA separates the interfaces and implementation, making it possible to include several [security providers](https://developer.android.com/reference/java/security/Provider.html "Android Security Providers") that can implement sets of cryptographic algorithms. Most of the JCA interfaces and classes are defined in the `java.security.*` and `javax.crypto.*` packages. In addition, there are Android specific packages `android.security.*` and `android.security.keystore.*`.

### Cryptography Implementations

#### Platform-Provided APIs

Google provides libraries that include implementations of most common cryptographic algorithms. The ["Android Cryptography Guide"](https://developer.android.com/guide/topics/security/cryptography "Cryptography") is a great reference. It contains generalized documentation of how to use standard libraries to initialize and use cryptographic primitives, information that is useful for source code analysis.

#### Third Party Libraries

There are various third party libraries available, such as:

- **LibSodium**: Sodium is a modern, easy-to-use software library for encryption, decryption, signatures, password hashing and more. It is a portable, cross-compilable, installable, packageable fork of [NaCl](http://nacl.cr.yp.to/), with a compatible API, and an extended API to improve usability even further. See [LibSodiums documentation](https://download.libsodium.org/doc/installation "LibSodium docs") for more details. There are some wrapper libraries, such as [libsodium for Android](https://github.com/terl/lazysodium-android).
- **Tink**: Tink was built by Google on top of existing libraries such as BoringSSL and Java Cryptography Architecture, but includes countermeasures to many weaknesses in these libraries. Google explains its reasoning behind the library [on its security blog](https://security.googleblog.com/2018/08/introducing-tink-cryptographic-software.html "Introducing Tink"). The sources can be found at [Tinks GitHub repository](https://github.com/google/tink "Tink at GitHub").
- **Themis**: [Themis](https://github.com/cossacklabs/themis "Themis") is a library for storage and messaging which uses LibreSSL/OpenSSL engine libcrypto as a dependency. It supports Java and Kotlin for key generation, secure messaging (e.g. payload encryption and signing), secure storage and setting up a secure session. See [their wiki](https://docs.cossacklabs.com/themis/languages/kotlin/ "Themis wiki") for more details.

**IMPORTANT NOTE:** This is by no means a complete overview of all existing cryptographic libraries nor it's a list of recommended libraries. The app developers are solely responsible for choosing secure and well-maintained libraries.

#### Custom Cryptographic Implementations

An increasing amount of developers have created their own implementation of a cipher or a cryptographic function. This practice is _highly_ discouraged and should be vetted very thoroughly by a cryptography expert if used.

#### Android Security Provider

Android relies on a security [`Provider`](https://developer.android.com/reference/java/security/Provider) to implement Java Security services. That is crucial to ensure secure network communications and secure other functionalities which depend on cryptography. This provider implements some or all parts of Java Security such as:

- Algorithms (such as DSA, RSA, MD5 or SHA-1).
- Key generation, conversion, and management facilities (such as for algorithm-specific keys).

These are some general recommendations regarding the Android Security provider:

- Apps should avoid specifying a security provider and use the default implementation (AndroidOpenSSL, Conscrypt).
- Apps should avoid using Crypto security provider and its `SHA1PRNG` as they are deprecated.
- Apps should specify a security provider only for the Android Keystore system.

**Listing Security Providers:**

The list of security providers included in Android varies between versions of Android and the OEM-specific builds. Some security provider implementations in older versions are now known to be less secure or vulnerable. Thus, Android applications should not only choose the correct algorithms and provide good configuration, in some cases they should also pay attention to the strength of the implementations in the legacy security providers.

Apps can list the set of existing security providers using following code:

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

Below you can find the output of a running Android 9 (API level 28) in an emulator with Google Play APIs:

```default
provider: AndroidNSSP 1.0(Android Network Security Policy Provider)
provider: AndroidOpenSSL 1.0(Android's OpenSSL-backed security provider)
provider: CertPathProvider 1.0(Provider of CertPathBuilder and CertPathVerifier)
provider: AndroidKeyStoreBCWorkaround 1.0(Android KeyStore security provider to work around Bouncy Castle)
provider: BC 1.57(BouncyCastle Security Provider v1.57)
provider: HarmonyJSSE 1.0(Harmony JSSE Provider)
provider: AndroidKeyStore 1.0(Android KeyStore security provider)
```

**Updating security provider:**

Keeping up-to-date and patched components is an essential security principle. Apps should check if the used Android Security Provider is up-to-date and if not, [update it](https://developer.android.com/training/articles/security-gms-provider "Updating security provider"). Testing the Android Security Provider should be done along with the test ["Checking for Weaknesses in Third Party Libraries (MSTG-CODE-5)"](0x05i-Testing-Code-Quality-and-Build-Settings.md#checking-for-weaknesses-in-third-party-libraries).

**Older Android versions:**

For some applications that support older versions of Android (e.g.: only used versions lower than Android 7.0 (API level 24)), bundling an up-to-date library may be the only option. Spongy Castle (a repackaged version of Bouncy Castle) is a common choice in these situations. Repackaging is necessary because Bouncy Castle is included in the Android SDK. The latest version of [Spongy Castle](https://rtyley.github.io/spongycastle/ "Spongy Castle") likely fixes issues encountered in the earlier versions of [Bouncy Castle](https://www.cvedetails.com/vulnerability-list/vendor_id-7637/Bouncycastle.html "CVE Details Bouncy Castle") that were included in Android. Note that the Bouncy Castle libraries packed with Android are often not as complete as their counterparts from the [legion of the Bouncy Castle](https://www.bouncycastle.org/java.html "Bouncy Castle in Java"). Lastly: bear in mind that packing large libraries such as Spongy Castle will often lead to a multidexed Android application.

### Key Management

KeyStore and KeyChain provide APIs for storing and using keys (behind the scene, KeyChain API uses KeyStore system). These systems allow to administer the full lifecycle of the cryptographic keys. Requirements and guidance for implementation of cryptographic key management can be found in [Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html "Key Management Cheat Sheet"). We can identify following phases:

- generating a key
- using a key
- storing a key
- archiving a key
- deleting a key

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

#### Key Storage

##### Avoid Storing Keys by using Key Derivation

Not storing a key at all will ensure that no key material can be dumped. This can be achieved by using a Password [Key Derivation](#key-derivation) function, such as PKBDF-2. Note that if you have a predictable key derivation function based on identifiers which are accessible to other applications, the attacker only needs to find the KDF and apply it to the device in order to find the key.

##### Using the KeyStore

If you need to store a key for repeated use, it is a best practice to use the Android KeyStore, that provides long term storage and retrieval of cryptographic keys. Key Storage using the Android KeyStore is analyzed in the chapter ["Testing Data Storage"](0x05d-Testing-Data-Storage.md).

##### Hardcoded Keys

Apps must avoid hardcoding encryption keys, as this would mean that every instance of the application uses the same encryption key. An attacker needs only to do the work once in order to extract the key from the source code (whether stored natively or in Objective-C/Swift). Consequently, the attacker can decrypt any other data that was encrypted by the application.

However, note that there is a widespread false believe that the NDK should be used to hide cryptographic operations and hardcoded keys. Attackers can still use tools to find the mechanism used and make dumps of the key in memory. Next, the control flow can be analyzed with e.g. radare2 and the keys extracted with the help of Frida or the combination of both: [r2frida](0x08a-Testing-Tools.md#r2frida) (see sections "[Disassembling Native Code](0x05c-Reverse-Engineering-and-Tampering.md#disassembling-native-code "Disassembling Native Code")", "[Memory Dump](0x05c-Reverse-Engineering-and-Tampering.md#memory-dump "Memory Dump")" and "[In-Memory Search](0x05c-Reverse-Engineering-and-Tampering.md#in-memory-search "In-Memory Search")" in the chapter "Tampering and Reverse Engineering on Android" for more details).

From Android 7.0 (API level 24) onward, it is not allowed to use private APIs, instead: public APIs need to be called, which further impacts the effectiveness of hiding it away as described in the [Android Developers Blog](https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html "Android changes for NDK developers").

#### Key Generation

Android SDK provides mechanisms for specifying secure key generation and use. Android 6.0 (API level 23) introduced the `KeyGenParameterSpec` class that can be used to ensure the correct key usage in the application.

##### AES Keys

Prior to Android 6.0 (API level 23), AES key generation was not supported. As a result, many implementations chose to use RSA and generated a public-private key pair for asymmetric encryption using `KeyPairGeneratorSpec` or used `SecureRandom` to generate AES keys.

Here's an example of using AES/CBC/PKCS7Padding on Android 6.0 (API level 23):

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

The `KeyGenParameterSpec` indicates that the key can be used for encryption and decryption, but not for other purposes, such as signing or verifying. It further specifies the block mode (CBC), padding (PKCS #7), and explicitly specifies that randomized encryption is required (this is the default). `"AndroidKeyStore"` is the name of security provider used in this example. This will automatically ensure that the keys are stored in the `AndroidKeyStore` which is beneficiary for the protection of the key.

GCM is another AES block mode that provides additional security benefits over other, older modes. In addition to being cryptographically more secure, it also provides authentication. When using CBC (and other modes), authentication would need to be performed separately, using HMACs (see the "[Tampering and Reverse Engineering on Android](0x05c-Reverse-Engineering-and-Tampering.md)" chapter). Note that GCM is the only mode of AES that [does not support paddings](https://developer.android.com/training/articles/keystore.html#SupportedCiphers "Supported Ciphers in AndroidKeyStore").

Attempting to use the generated key in violation of the above spec would result in a security exception.

**Encryption:**

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

Since the IV (initialization vector) is randomly generated each time, it should be saved along with the cipher text (`encryptedBytes`); otherwise decryption is not possible.

**Decryption:**

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

##### RSA Key Pair

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

#### Key Derivation

A symmetric encryption key can be generated from the passphrase by using the Password Based Key Derivation Function version 2 (PBKDF2). This cryptographic protocol is designed to generate cryptographic keys, which can be safely used for cryptography. Input parameters for the algorithm are adjusted according to [weak key generation function](0x04g-Testing-Cryptography.md#weak-key-generation-functions) section. The code listing below illustrates how to generate a strong encryption key based on a password.

```java
public static SecretKey generatePasswordBasedAESKey(char[] password, int keyLength)
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

The above method requires a character array containing the password and the needed key length in bits, for instance a 128 or 256-bit AES key. We define an iteration count of 10,000 rounds which will be used by the PBKDF2 algorithm. Increasing number of iteration significantly increases the workload for a brute-force attack on password, however it can affect performance as more computational power is required for key derivation. We define the salt size equal to the key length, we divide by 8 to take care of the bit to byte conversion. We use the `SecureRandom` class to randomly generate a salt. Obviously, the salt is something you want to keep constant to ensure the same encryption key is generated time after time for the same supplied password. Note that you can store the salt privately in `SharedPreferences`. It is recommended to exclude the salt from the Android backup mechanism to prevent synchronization in case of higher risk data.

> Note that if you take a rooted device or a patched (e.g. repackaged) application into account as a threat to the data, it might be better to encrypt the salt with a key that is placed in the Android Keystore. The Password-Based Encryption (PBE) key is generated using the recommended `PBKDF2WithHmacSHA1` algorithm, till Android 8.0 (API level 26). For higher API levels, it is best to use `PBKDF2withHmacSHA256`, which will end up with a longer hash value.

### Random Number Generation

Cryptography requires secure pseudo random number generation (PRNG). Standard Java classes as `java.util.Random` do not provide sufficient randomness and in fact may make it possible for an attacker to guess the next value that will be generated, and use this guess to impersonate another user or access sensitive information.

In general, `SecureRandom` should be used. However, if the Android versions below Android 4.4 (API level 19) are supported, additional care needs to be taken in order to work around the bug in Android 4.1-4.3 (API level 16-18) versions that [failed to properly initialize the PRNG](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html "Some SecureRandom Thoughts").

Most developers should instantiate `SecureRandom` via the default constructor without any arguments. Other constructors are for more advanced uses and, if used incorrectly, can lead to decreased randomness and security. The PRNG provider backing `SecureRandom` uses the `SHA1PRNG` from `AndroidOpenSSL` (Conscrypt) provider.

In general, if a PRNG is not advertised as being cryptographically secure (e.g. `java.util.Random`), then it is probably a statistical PRNG and should not be used in security-sensitive contexts.
Pseudo-random number generators [can produce predictable numbers](https://www.securecoding.cert.org/confluence/display/java/MSC63-J.+Ensure+that+SecureRandom+is+properly+seeded "Proper seeding of SecureRandom") if the generator is known and the seed can be guessed. A 128-bit seed is a good starting point for producing a "random enough" number.

Once an attacker knows what type of weak pseudo-random number generator (PRNG) is used, it can be trivial to write a proof-of-concept to generate the next random value based on previously observed ones, as it was [done for Java Random](https://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/ "Predicting the next Math.random() in Java"). In case of very weak custom random generators it may be possible to observe the pattern statistically. Although the recommended approach would anyway be to decompile the app and inspect the algorithm.

## Testing for Symmetric Cryptography Using Hardcoded Keys (MSTG-CRYPTO-1)

### Overview

This test case focuses on hardcoded symmetric cryptography as the only method of encryption. The following checks should be performed:

- identify all instances of symmetric cryptography
- for each identified instance verify if there are any hardcoded symmetric keys
- verify if hardcoded symmetric cryptography is not used as the only method of encryption

### Static Analysis

Identify all the instances of symmetric key encryption in code and look for any mechanism which loads or provides a symmetric key. You can look for:

- symmetric algorithms (such as `DES`, `AES`, etc.)
- specifications for a key generator (such as `KeyGenParameterSpec`, `KeyPairGeneratorSpec`, `KeyPairGenerator`, `KeyGenerator`, `KeyProperties`, etc.)
- classes importing `java.security.*`, `javax.crypto.*`, `android.security.*`, `android.security.keystore.*`

For each identified instance verify if the used symmetric keys:

- are not part of the application resources
- cannot be derived from known values
- are not hardcoded in code

For each hardcoded symmetric key, verify that is not used in security-sensitive contexts as the only method of encryption.

As an example we illustrate how to locate the use of a hardcoded encryption key. First [disassemble and decompile](0x05c-Reverse-Engineering-and-Tampering.md#disassembling-and-decompiling) the app to obtain Java code, e.g. by using [jadx](0x08a-Testing-Tools.md#jadx).

Now search the files for the usage of the `SecretKeySpec` class, e.g. by simply recursively grepping on them or using jadx search function:

```bash
grep -r "SecretKeySpec"
```

This will return all classes using the `SecretKeySpec` class. Now examine those files and trace which variables are used to pass the key material. The figure below shows the result of performing this assessment on a production ready application. We can clearly locate the use of a static encryption key that is hardcoded and initialized in the static byte array `Encrypt.keyBytes`.

<img src="Images/Chapters/0x5e/static_encryption_key.png" width="600px"/>

### Dynamic Analysis

You can use [method tracing](0x05c-Reverse-Engineering-and-Tampering.md#method-tracing) on cryptographic methods to determine input / output values such as the keys that are being used. Monitor file system access while cryptographic operations are being performed to assess where key material is written to or read from. For example, monitor the file system by using the [API monitor](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security#8-api-monitor---android-only) of [RMS - Runtime Mobile Security](0x08a-Testing-Tools.md#RMS-Runtime-Mobile-Security).

## Testing for Insecure Cryptography Implementations (MSTG-CRYPTO-2)

### Overview

This test checks if the app uses any potentially insecure cryptographic implementations. You can find more information in section "Cryptography Implementations" in the chapter ["Cryptography for Mobile Apps"](0x04g-Testing-Cryptography.md).

### Static Analysis

First of of check if the app mostly relies on **platform-provided** cryptographic implementations. See section ["Platform-Provided APIs"](#platform-provided-apis) for more information.

- classes `Cipher`, `Mac`, `MessageDigest`, `Signature`
- interfaces `Key`, `PrivateKey`, `PublicKey`, `SecretKey`
- functions `getInstance`, `generateKey`
- exceptions `KeyStoreException`, `CertificateException`, `NoSuchAlgorithmException`
- classes which uses `java.security.*`, `javax.crypto.*`, `android.security.*` and `android.security.keystore.*` packages

Check the specified security providers:

- Check calls to `getInstance` and ensure that they **are not** specifying any security provider. By doing this it is ensured that they are using the default security provider (AndroidOpenSSL aka Conscrypt).
- Check code using the `android.security.keystore.*` package and ensure that `KeyStore` is specified as `provider`. If another provider is specified it should be verified according to situation and business case (i.e. Android API version), and that provider should be examined against potential vulnerabilities.

Check the list of **third-party** libraries used by the app. You should have a list of them after performing the test in ["Checking for Weaknesses in Third Party Libraries (MSTG-CODE-5)"](0x05i-Testing-Code-Quality-and-Build-Settings.md#checking-for-weaknesses-in-third-party-libraries). You can also use the references we provide in section ["Third-Party Libraries"](#third-party-libraries) as a starting point.

Lastly, check if the app has any **custom** cryptographic implementations (aka. _rolls its own crypto_), for instance by searching for well-known cryptographic constants (find more information [here](https://www.mi.fu-berlin.de/inf/groups/ag-idm/members/8_ehemalige-Mitarbeiter_innen/Tim-Ohlendorf/ma_ohlendorf_tim.pdf)). Pay attention to how data structures holding cryptographic keys and plaintext are defined and how they are cleaned up (wiped or zeroized).

## Testing for Common Cryptography Configuration Issues (MSTG-CRYPTO-3)

### Overview

This test focuses on verifying if cryptography primitives are configured and used according to current best practices.

### Static Analysis

Identify all the uses of cryptography within code.

For all platform-provided APIs found, ensure that they are using according to all platform best practices specified in the ["Android Cryptography Guide"](https://developer.android.com/guide/topics/security/cryptography) and the ["Android Security Tips for Cryptography"](https://developer.android.com/training/articles/security-tips#Crypto). For example:

- Check if the app uses the algorithms recommended by Google:
  - Cipher: AES in either CBC or GCM mode with 256-bit keys (such as AES/GCM/NoPadding)
  - MessageDigest: SHA-2 family (such as SHA-256)
  - Mac: SHA-2 family HMAC (such as HMACSHA256)
  - Signature: SHA-2 family with ECDSA (such as SHA256withECDSA)
- Check for any [deprecated functionality](https://developer.android.com/guide/topics/security/cryptography#deprecated-functionality) in use.

Ensure that all other general best practices outlined in the "[Cryptography for Mobile Apps](0x04g-Testing-Cryptography.md)" chapter are followed.

### Dynamic Analysis

You can use [method tracing](0x05c-Reverse-Engineering-and-Tampering.md#method-tracing) on cryptographic methods to determine input / output values such as the keys that are being used. Monitor file system access while cryptographic operations are being performed to assess where key material is written to or read from. For example, monitor the file system by using the [API monitor](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security#8-api-monitor---android-only) of [RMS - Runtime Mobile Security](0x08a-Testing-Tools.md#RMS-Runtime-Mobile-Security).

## Testing the Purposes of Keys (MSTG-CRYPTO-5)

### Overview

This test case focuses on verification of purpose and reuse of cryptographic keys. The following checks should be performed:

- identify all instances where cryptography is used
- identify the purpose of the cryptographic material (to protect data in use, in transit or at rest)
- identify type of cryptography
- verify if cryptography is used according to its purpose

### Static Analysis

Identify all instances where cryptography is used. You can look for:

- classes `Cipher`, `Mac`, `MessageDigest`, `Signature`
- interfaces `Key`, `PrivateKey`, `PublicKey`, `SecretKey`
- functions `getInstance`, `generateKey`
- exceptions `KeyStoreException`, `CertificateException`, `NoSuchAlgorithmException`
- classes importing `java.security.*`, `javax.crypto.*`, `android.security.*`, `android.security.keystore.*`

For each identified instance, identify its purpose and its type. It can be used:

- for encryption/decryption - to ensure data confidentiality
- for signing/verifying - to ensure integrity of data (as well as accountability in some cases)
- for maintenance - to protect keys during certain sensitive operations (such as being imported to the KeyStore)

Additionally, you should identify the business logic which uses identified instances of cryptography.

During verification the following checks should be performed:

- are all keys used according to the purpose defined during its creation? (it is relevant to KeyStore keys, which can have KeyProperties defined)
- for asymmetric keys, is the private key being exclusively used for signing and the public key encryption?
- are symmetric keys used for multiple purposes? A new symmetric key should be generated if it's used in a different context.
- is cryptography used according to its business purpose?

### Dynamic Analysis

You can use [method tracing](0x05c-Reverse-Engineering-and-Tampering.md#method-tracing) on cryptographic methods to determine input / output values such as the keys that are being used. Monitor file system access while cryptographic operations are being performed to assess where key material is written to or read from. For example, monitor the file system by using the [API monitor](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security#8-api-monitor---android-only) of [RMS - Runtime Mobile Security](0x08a-Testing-Tools.md#RMS-Runtime-Mobile-Security).

## Testing Random Number Generation (MSTG-CRYPTO-6)

### Overview

This test case focuses on random values used by application. The following checks should be performed:

- identify all instances where random values are used
- verify if random number generators are not considered as being cryptographically secure
- verify how random number generators are used
- verify randomness of the generated random values (optional)

### Static Analysis

Identify all the instances of random number generators and look for either custom or well-known insecure classes. For instance, `java.util.Random` produces an identical sequence of numbers for each given seed value; consequently, the sequence of numbers is predictable. Instead a well-vetted algorithm should be chosen that is currently considered to be strong by experts in the field, and a well-tested implementations with adequate length seeds should be used.

If the app is using `SecureRandom`:

- Identify all instances of `SecureRandom` that are not created using the default constructor. Specifying the seed value may reduce randomness.
- Check if it uses the [no-argument constructor of `SecureRandom`](https://www.securecoding.cert.org/confluence/display/java/MSC02-J.+Generate+strong+random+numbers "Generation of Strong Random Numbers") that uses the system-specified seed value to generate a 128-byte-long random number.

Note (optional): If you want to test for randomness, you can try to capture a large set of numbers and check with the Burp's [sequencer](https://portswigger.net/burp/documentation/desktop/tools/sequencer "Burp\'s Sequencer") to see how good the quality of the randomness is.

### Dynamic Analysis

You can use [method tracing](0x05c-Reverse-Engineering-and-Tampering.md#method-tracing) on the mentioned classes and methods to determine input/output values being used.

## References

- [#nelenkov] - N. Elenkov, Android Security Internals, No Starch Press, 2014, Chapter 5.

### Cryptography references

- Android Developer blog: Changes for NDK Developers - <https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html>
- Android Developer blog: Crypto Provider Deprecated - <https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html>
- Android Developer blog: Cryptography Changes in Android P - <https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html>
- Android Developer blog: Some SecureRandom Thoughts - <https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html>
- Android Developer documentation - <https://developer.android.com/guide>
- BSI Recommendations - <https://www.keylength.com/en/8/>
- Ida Pro - <https://www.hex-rays.com/products/ida/>
- Legion of the Bouncy Castle - <https://www.bouncycastle.org/java.html>
- NIST Key Length Recommendations - <https://www.keylength.com/en/4/>
- Security Providers - <https://developer.android.com/reference/java/security/Provider.html>
- Spongy Castle - <https://rtyley.github.io/spongycastle/>

### SecureRandom references

- BurpProxy Sequencer - <https://portswigger.net/burp/documentation/desktop/tools/sequencer>
- Proper Seeding of SecureRandom - <https://www.securecoding.cert.org/confluence/display/java/MSC63-J.+Ensure+that+SecureRandom+is+properly+seeded>

### Testing Key Management references

- Android Keychain API - <https://developer.android.com/reference/android/security/KeyChain>
- Android KeyStore API - <https://developer.android.com/reference/java/security/KeyStore.html>
- Android Keystore system - <https://developer.android.com/training/articles/keystore#java>
- Android Pie features and APIs - <https://developer.android.com/about/versions/pie/android-9.0#secure-key-import>
- KeyInfo Documentation - <https://developer.android.com/reference/android/security/keystore/KeyInfo>
- SharedPreferences - <https://developer.android.com/reference/android/content/SharedPreferences.html>

### Key Attestation References

- Android Key Attestation - <https://developer.android.com/training/articles/security-key-attestation>
- Attestation and Assertion - <https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Attestation_and_Assertion>
- FIDO Alliance TechNotes - <https://fidoalliance.org/fido-technotes-the-truth-about-attestation/>
- FIDO Alliance Whitepaper - <https://fidoalliance.org/wp-content/uploads/Hardware-backed_Keystore_White_Paper_June2018.pdf>
- Google Sample Codes - <https://github.com/googlesamples/android-key-attestation/tree/master/server>
- Verifying Android Key Attestation - <https://medium.com/@herrjemand/webauthn-fido2-verifying-android-keystore-attestation-4a8835b33e9d>
- W3C Android Key Attestation - <https://www.w3.org/TR/webauthn/#android-key-attestation>

#### OWASP MASVS

- MSTG-STORAGE-1: "System credential storage facilities need to be used to store sensitive data, such as PII, user credentials or cryptographic keys."
- MSTG-CRYPTO-1: "The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption."
- MSTG-CRYPTO-2: "The app uses proven implementations of cryptographic primitives."
- MSTG-CRYPTO-3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices."
- MSTG-CRYPTO-5: "The app doesn't re-use the same cryptographic key for multiple purposes."
- MSTG-CRYPTO-6: "All random values are generated using a sufficiently secure random number generator."
