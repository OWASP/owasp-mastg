## Android Cryptographic APIs

### Overview

In the chapter "[Cryptography for Mobile Apps](0x04g-Testing-Cryptography.md)", we introduced general cryptography best practices and described typical flaws that can occur when cryptography is used incorrectly in mobile apps. In this chapter, we'll go into more detail on Android's cryptography APIs. We'll show how to identify uses of those APIs in the source code and how to interpret the configuration. When reviewing code, make sure to compare the cryptographic parameters used with the current best practices linked from this guide.

We can identify key components of cryptography system in Android:

- [Security Provider](0x05e-Testing-Cryptography.md#security-provider)
- KeyStore - see the section [KeyStore](0x05d-Testing-Data-Storage.md#keystore) in the chapter "Testing Data Storage"
- KeyChain - see the section [KeyChain](0x05d-Testing-Data-Storage.md#keychain) in the chapter "Testing Data Storage"

Android cryptography APIs are based on the Java Cryptography Architecture (JCA). JCA separates the interfaces and implementation, making it possible to include several [security providers](https://developer.android.com/reference/java/security/Provider.html "Android Security Providers") that can implement sets of cryptographic algorithms. Most of the JCA interfaces and classes are defined in the `java.security.*` and `javax.crypto.*` packages. In addition, there are Android specific packages `android.security.*` and `android.security.keystore.*`.

KeyStore and KeyChain provide APIs for storing and using keys (behind the scene, KeyChain API uses KeyStore system). These systems allow to administer the full lifecycle of the cryptographic keys. Requirements and guidance for implementation of cryptographic key management can be found in [Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html "Key Management Cheat Sheet"). We can identify following phases:

- generating of a key
- using of a key
- storing of a key
- archiving of a key
- deleting a key

> Please note that storing of a key is analyzed in the chapter "[Testing Data Storage](0x05d-Testing-Data-Storage.md)".

These phases are managed by Keystore/KeyChain system. However how the system works depends on how application developer used it. Then, you should focus on functions which are used by application developer. You should identify and verify following functions:

- [Key generation](0x05e-Testing-Cryptography.md#key-generation)
- [Random number generation](0x05e-Testing-Cryptography.md#random-number-generation)
- Key rotation

Apps that target modern API levels, went through the following changes:

- For Android 7.0 (API level 24) and above [the Android Developer blog shows that](https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html "Security provider Crypto deprecated in Andorid N"):
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

#### Recommendation

The following list of recommendations should be considered during app examination:

- You should ensure that the best practices outlined in the "[Cryptography for Mobile Apps](0x04g-Testing-Cryptography.md)" chapter are followed.
- You should ensure that security provider has the latest updates - [Updating security provider](https://developer.android.com/training/articles/security-gms-provider "Updating security provider").
- You should stop specifying a security provider and use the default implementation (AndroidOpenSSL, Conscrypt).
- You should stop using Crypto security provider and its `SHA1PRNG` as they are depracated.
- You should specify a security provider only for the Android Keystore system.
- You should stop using Password-based encryption ciphers without IV.
- You should use KeyGenParameterSpec instead of KeyPairGeneratorSpec.

#### Security provider

Android relies on `provider` to implement Java Security services. That is crucial to ensure secure network communications and secure other functionalities which depend on cryptography.  

The list of security providers included in Android varies between versions of Android and the OEM-specific builds. Some security provider implementations in older versions are now known to be less secure or vulnerable. Thus, Android applications should not only choose the correct algorithms and provide good configuration, in some cases they should also pay attention to the strength of the implementations in the legacy security providers.

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

Below you can find the output of a running Android 4.4 (API level 19) in an emulator with Google Play APIs, after the security provider has been patched:

```text
provider: GmsCore_OpenSSL1.0 (Android's OpenSSL-backed security provider)
provider: AndroidOpenSSL1.0 (Android's OpenSSL-backed security provider)
provider: DRLCertFactory1.0 (ASN.1, DER, PkiPath, PKCS7)
provider: BC1.49 (BouncyCastle Security Provider v1.49)
provider: Crypto1.0 (HARMONY (SHA1 digest; SecureRandom; SHA1withDSA signature))
provider: HarmonyJSSE1.0 (Harmony JSSE Provider)
provider: AndroidKeyStore1.0 (Android AndroidKeyStore security provider)
```

Below you can find the output of a running Android 9 (API level 28) in an emulator with Google Play APIs:

```text
provider: AndroidNSSP 1.0(Android Network Security Policy Provider)
provider: AndroidOpenSSL 1.0(Android's OpenSSL-backed security provider)
provider: CertPathProvider 1.0(Provider of CertPathBuilder and CertPathVerifier)
provider: AndroidKeyStoreBCWorkaround 1.0(Android KeyStore security provider to work around Bouncy Castle)
provider: BC 1.57(BouncyCastle Security Provider v1.57)
provider: HarmonyJSSE 1.0(Harmony JSSE Provider)
provider: AndroidKeyStore 1.0(Android KeyStore security provider)
```

##### Updating security provider

Keeping up-to-date and patched component is one of security principles. The same applies to `provider`. Application should check if used security provider is up-to-date and if not, [update it](https://developer.android.com/training/articles/security-gms-provider "Updating security provider"). It is related to [Checking for Weaknesses in Third Party Libraries (MSTG-CODE-5)](0x05i-Testing-Code-Quality-and-Build-Settings.md#checking-for-weaknesses-in-third-party-libraries).

##### Older Android versions

For some applications that support older versions of Android (e.g.: only used versions lower than Android 7.0 (API level 24)), bundling an up-to-date library may be the only option. Spongy Castle (a repackaged version of Bouncy Castle) is a common choice in these situations. Repackaging is necessary because Bouncy Castle is included in the Android SDK. The latest version of [Spongy Castle](https://rtyley.github.io/spongycastle/ "Spongy Castle") likely fixes issues encountered in the earlier versions of [Bouncy Castle](https://www.cvedetails.com/vulnerability-list/vendor_id-7637/Bouncycastle.html "CVE Details Bouncy Castle") that were included in Android. Note that the Bouncy Castle libraries packed with Android are often not as complete as their counterparts from the [legion of the Bouncy Castle](https://www.bouncycastle.org/java.html "Bouncy Castle in Java"). Lastly: bear in mind that packing large libraries such as Spongy Castle will often lead to a multidexed Android application.

#### Key Generation

Android SDK provides mechanisms for specifying secure key generation and use. Android 6.0 (API level 23) introduced the `KeyGenParameterSpec` class that can be used to ensure the correct key usage in the application.

Here's an example of using AES/CBC/PKCS7Padding on API 23+:

```Java
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

Here's an example of using that key to encrypt:

```Java
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

```Java
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

```Java
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

This sample creates the RSA key pair with a key size of 4096-bit (i.e. modulus size).

A symmetric encryption key can be generated from the passphrase by using the Password Based Key Derivation Function version 2 (PBKDF2). This cryptographic protocol is designed to generate a cryptographic keys, which can be used for cryptography purpose. Input parameters for the algorithm are adjusted according to [weak key generation function](0x04g-Testing-Cryptography.md#weak-key-generation-functions) section. The code listing below illustrates how to generate a strong encryption key based on a password.

```java
public static SecretKey generateStrongAESKey(char[] password, int keyLength)
{
    //Initiliaze objects and variables for later use
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

The above method requires a character array containing the password and the needed key length in bits, for instance a 128 or 256-bit AES key. We define an iteration count of 10000 rounds which will be used by the PBKDF2 algorithm. Increasing number of iteration significantly increases the workload for a brute-force attack on password, however it can affect performance as more computational power is required for key derivation. We define the salt size equal to the key length, we divide by 8 to take care of the bit to byte conversion. We use the `SecureRandom` class to randomly generate a salt. Obviously, the salt is something you want to keep constant to ensure the same encryption key is generated time after time for the same supplied password. Note that you can store the salt privately in `SharedPreferences`. It is recommended to exclude the salt from the Android backup mechanism to prevent synchronization in case of higher risk data.

> Note that if you take a rooted device or a patched (e.g. repackaged) application into account as a threat to the data, it might be better to encrypt the salt with a key that is placed in the `AndroidKeystore`. The Password-Based Encryption (PBE) key is generated using the recommended `PBKDF2WithHmacSHA1` algorithm, till Android 8.0 (API level 26). For higher API levels, it is best to use `PBKDF2withHmacSHA256`, which will end up with a longer hash value.

Note: there is a widespread false believe that the NDK should be used to hide cryptographic operations and hardcoded keys. However, using this mechanisms is not effective. Attackers can still use tools to find the mechanism used and make dumps of the key in memory. Next, the control flow can be analyzed with e.g. radare2 and the keys extracted with the help of Frida or the combination of both: r2frida (see sections "[Disassembling Native Code](0x05c-Reverse-Engineering-and-Tampering.md#disassembling-native-code "Disassembling Native Code")", "[Memory Dump](0x05c-Reverse-Engineering-and-Tampering.md#memory-dump "Memory Dump")" and "[In-Memory Search](0x05c-Reverse-Engineering-and-Tampering.md#in-memory-search "In-Memory Search")" in the chapter "Tampering and Reverse Engineering on Android" for more details). From Android 7.0 (API level 24) onward, it is not allowed to use private APIs, instead: public APIs need to be called, which further impacts the effectiveness of hiding it away as described in the [Android Developers Blog](https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html "Android changes for NDK developers")

#### Random number generation

Cryptography requires secure pseudo random number generation (PRNG). Standard Java class (means java.util.Random) does not provide sufficient randomness and in fact may make it possible for an attacker to guess the next value that will be generated, and use this guess to impersonate another user or access sensitive information.

In general, `SecureRandom` should be used. However, if the Android versions below Android 4.4 (API level 19) are supported, additional care needs to be taken in order to work around the bug in Android 4.1-4.3 (API level 16-18) versions that [failed to properly initialize the PRNG](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html "Some SecureRandom Thoughts").

Most developers should instantiate `SecureRandom` via the default constructor without any arguments. Other constructors are for more advanced uses and, if used incorrectly, can lead to decreased randomness and security. The PRNG provider backing `SecureRandom` uses the `SHA1PRNG` from `AndroidOpenSSL` (Conscrypt) provider.

### Testing Symmetric Cryptography (MSTG-CRYPTO-1)

#### Overview

This test case focuses on hardcoded symmetric cryptography as the only method of encryption. Following checks should be performed:

- identify all instance of symmectric cryptography
- verify if symmetric keys in all identified instances are not hardcoded
- verify if hardcoded symmetric cryptography is not used as the only method of encryption

#### Static Analysis

Identify all the instances of symmetric key encryption in code and look for mechanism which loads or provides a symmetric key. You can look for:

- symmetric algorithms (like `DES`, `AES`, etc.)
- specifications for a key generator (like `KeyGenParameterSpec`, `KeyPairGeneratorSpec`, `KeyPairGenerator`, `KeyGenerator`, `KeyProperties`, etc.)
- classes which uses `java.security.*`, `javax.crypto.*`, `android.security.*` and `android.security.keystore.*` packages.

Verify that symmetric keys in all identified instances are not hardcoded. Check if symmetric keys are not:

- part of application resources
- values which can be derived from known values
- hardcoded in code

Verify that all identified instances of hardcoded symmetric cryptography is not used in security-sensitive contexts as the only method of encryption.

As an example we illustrate how to locate the use of a hardcoded encryption key. First disassemble the DEX bytecode to a collection of Smali bytecode files using ```Baksmali```.

```shell
$ baksmali d file.apk -o smali_output/
```

Now that we have a collection of Smali bytecode files, we can search the files for the usage of the ```SecretKeySpec``` class. We do this by simply recursively grepping on the Smali source code we just obtained. Please note that class descriptors in Smali start with `L` and end with `;`:

```shell
$ grep -r "Ljavax\crypto\spec\SecretKeySpec;"
```

This will highlight all the classes that use the `SecretKeySpec` class, we now examine all the highlighted files and trace which bytes are used to pass the key material. The figure below shows the result of performing this assessment on a production ready application. For sake of readability we have reverse engineered the DEX bytecode to Java code. We can clearly locate the use of a static encryption key that is hardcoded and initialized in the static byte array `Encrypt.keyBytes`.

<img src="Images/Chapters/0x5e/static_encryption_key.png" width="600px"/>

#### Dynamic Analysis

Hook cryptographic methods and analyze the keys that are being used. Monitor file system access while cryptographic operations are being performed to assess where key material is written to or read from.

### Testing the Configuration of Cryptographic Standard Algorithms (MSTG-CRYPTO-2, MSTG-CRYPTO-3 and MSTG-CRYPTO-4)

#### Overview

These test cases focus on implementation and use of cryptographic primitives. Following checks should be performed:

- identify all instance of cryptography primitives and their implementation (library or custom implementation)
- verify how cryptography primitives are used and how they are configured
- verify if cryptographic protocols and algorithms used are not deprecated for security purposes.

#### Static Analysis

Identify all the instances of the cryptographic primitives in code. Identify all custom cryptography implementations. You can look for:

- classes `Cipher`, `Mac`, `MessageDigest`, `Signature`
- interfaces `Key`, `PrivateKey`, `PublicKey`, `SecretKey`
- functions `getInstance`, `generateKey`
- exceptions `KeyStoreException`, `CertificateException`, `NoSuchAlgorithmException`
- classes which uses `java.security.*`, `javax.crypto.*`, `android.security.*` and `android.security.keystore.*` packages.

Identify that all calls to getInstance use default `provider` of security services by not specifing it (it means AndroidOpenSSL aka Conscrypt). `Provider` can only be specified in `KeyStore` related code (in that situation `KeyStore` should be provided as `provider`). If other `provider` is specified it should be verified according to situation and business case (i.e. Android API version), and `provider` should be examined against potential vulnerabilities.  

Ensure that the best practices outlined in the "[Cryptography for Mobile Apps](0x04g-Testing-Cryptography.md)" chapter are followed. Look at [insecure and deprecated algorithms](0x04g-Testing-Cryptography.md#identifying-insecure-and/or-deprecated-cryptographic-algorithms) and [common configuration issues](0x04g-Testing-Cryptography.md#common-configuration-issues).

#### Dynamic Analysis

Hook cryptographic methods and analyze the keys that are being used. Monitor file system access while cryptographic operations are being performed to assess where key material is written to or read from.

### Testing the Purposes of Keys (MSTG-CRYPTO-5)

#### Overview

This test case focuses on verification of purpose and reusage of the same cryptographic keys. Following checks should be performed:

- identify all instanaces where cryptography is used
- identify purpose why cryptography is used (to protect data in use, in transit or at rest)
- identify type of cryptography
- verify if cryptography is used according to its purpose

#### Static Analysis

Identify all instanaces where cryptography is used. You can look for:

- classes `Cipher`, `Mac`, `MessageDigest`, `Signature`
- interfaces `Key`, `PrivateKey`, `PublicKey`, `SecretKey`
- functions `getInstance`, `generateKey`
- exceptions `KeyStoreException`, `CertificateException`, `NoSuchAlgorithmException`
- classes which uses `java.security.*`, `javax.crypto.*`, `android.security.*` and `android.security.keystore.*` packages.

For all identified instance, identify purpose of using cryptography and its type. It can be used :

- to encrypt/decrypt - that ensures confidentiality of data
- to sign/verify - that ensures integrity of data (as well as accountability in some cases)
- to maintance - that protects key during an operation (like import to KeyStore)

Additionally, you should identify business logic which uses identified instances of cryptography. That should give you explanation why cryptography is used from business perspective (i.e. to protect confidentiality of data at rest, to confirm that file was signed from device X which belongs to Y).

During verification take the following checks should be performed:

- make sure that key is used according to purpose defined during its creation (it is relevant to KeyStore keys, which can have KeyProperties defined)
- make sure that for asymmetric keys, the private key is exclusively used for signing and the public key is only used for encryption.
- make sure that symmetric keys are not reused for multiple purposes. A new symmetric key should be generated if it's used in a different context.
- make sure that cryptography is used according to business purpose.

#### Dynamic Analysis

Hook cryptographic methods and analyze the keys that are being used. Monitor file system access while cryptographic operations are being performed to assess where key material is written to or read from.

### Testing Random Number Generation (MSTG-CRYPTO-6)

#### Overview

This test case focuses on random values used by application. Following checks should be performed:

- identify all instances where random values are used and all instances of random number generators are of `Securerandom`
- verify if random number generators are not consider as being cryptographically secure
- verify how random number generators were used
- verify randomness of random values generated by application

#### Static Analysis

Identify all the instances of random number generators and look for either custom or known insecure `java.util.Random` class. This class produces an identical sequence of numbers for each given seed value; consequently, the sequence of numbers is predictable.

The following sample source code shows weak random number generation:

```Java
import java.util.Random;
// ...

Random number = new Random(123L);
//...
for (int i = 0; i < 20; i++) {
  // Generate another random integer in the range [0, 20]
  int n = number.nextInt(21);
  System.out.println(n);
}
```

Instead a well-vetted algorithm should be used that is currently considered to be strong by experts in the field, and select well-tested implementations with adequate length seeds.

Identify all instances of `SecureRandom` that are not created using the default constructor. Specifying the seed value may reduce randomness. Prefer the [no-argument constructor of `SecureRandom`](https://www.securecoding.cert.org/confluence/display/java/MSC02-J.+Generate+strong+random+numbers "Generation of Strong Random Numbers") that uses the system-specified seed value to generate a 128-byte-long random number.

In general, if a PRNG is not advertised as being cryptographically secure (e.g. `java.util.Random`), then it is probably a statistical PRNG and should not be used in security-sensitive contexts.
Pseudo-random number generators [can produce predictable numbers](https://www.securecoding.cert.org/confluence/display/java/MSC63-J.+Ensure+that+SecureRandom+is+properly+seeded "Proper seeding of SecureRandom") if the generator is known and the seed can be guessed. A 128-bit seed is a good starting point for producing a "random enough" number.

The following sample source code shows the generation of a secure random number:

```Java
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
// ...

public static void main (String args[]) {
  SecureRandom number = new SecureRandom();
  // Generate 20 integers 0..20
  for (int i = 0; i < 20; i++) {
    System.out.println(number.nextInt(21));
  }
}
```

#### Dynamic Analysis

Once an attacker is knowing what type of weak pseudo-random number generator (PRNG) is used, it can be trivial to write proof-of-concept to generate the next random value based on previously observed ones, as it was [done for Java Random](https://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/ "Predicting the next Math.random() in Java"). In case of very weak custom random generators it may be possible to observe the pattern statistically. Although the recommended approach would anyway be to decompile the APK and inspect the algorithm (see Static Analysis).

If you want to test for randomness, you can try to capture a large set of numbers and check with the Burp's [sequencer](https://portswigger.net/burp/documentation/desktop/tools/sequencer "Burp\'s Sequencer") to see how good the quality of the randomness is.

### References

- [#nelenkov] - N. Elenkov, Android Security Internals, No Starch Press, 2014, Chapter 5.

#### Cryptography references

- Android Developer blog: Changes for NDK Developers - <https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html>
- Android Developer blog: Crypto Provider Deprecated - <https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html>
- Android Developer blog: Cryptography Changes in Android P - <https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html>
- Android Developer blog: Some SecureRandom Thoughts - <https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html>
- Android Developer documentation - <https://developer.android.com/guide>
- BSI Recommendations - 2017 - <https://www.keylength.com/en/8/>
- Ida Pro - <https://www.hex-rays.com/products/ida/>
- Legion of the Bouncy Castle - <https://www.bouncycastle.org/java.html>
- NIST Key Length Recommendations - <https://www.keylength.com/en/4/>
- Security Providers -  <https://developer.android.com/reference/java/security/Provider.html>
- Spongy Castle  - <https://rtyley.github.io/spongycastle/>

#### SecureRandom references

- Burpproxy its Sequencer - <https://portswigger.net/burp/documentation/desktop/tools/sequencer>
- Proper Seeding of SecureRandom - <https://www.securecoding.cert.org/confluence/display/java/MSC63-J.+Ensure+that+SecureRandom+is+properly+seeded>

#### Testing Key Management references

- Android Keychain API - <https://developer.android.com/reference/android/security/KeyChain>
- Android KeyStore API - <https://developer.android.com/reference/java/security/KeyStore.html>
- Android Keystore system - <https://developer.android.com/training/articles/keystore#java>
- Android Pie features and APIs - <https://developer.android.com/about/versions/pie/android-9.0#secure-key-import>
- KeyInfo Documentation - <https://developer.android.com/reference/android/security/keystore/KeyInfo>
- SharedPreferences - <https://developer.android.com/reference/android/content/SharedPreferences.html>

#### Key Attestation References

- Android Key Attestation - <https://developer.android.com/training/articles/security-key-attestation>
- Attestation and Assertion - <https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Attestation_and_Assertion>
- FIDO Alliance TechNotes - <https://fidoalliance.org/fido-technotes-the-truth-about-attestation/>
- FIDO Alliance Whitepaper - <https://fidoalliance.org/wp-content/uploads/Hardware-backed_Keystore_White_Paper_June2018.pdf>
- Google Sample Codes - <https://github.com/googlesamples/android-key-attestation/tree/master/server>
- Verifying Android Key Attestation - <https://medium.com/@herrjemand/webauthn-fido2-verifying-android-keystore-attestation-4a8835b33e9d>
- W3C Android Key Attestation - <https://www.w3.org/TR/webauthn/#android-key-attestation>

##### OWASP MASVS

- MSTG-STORAGE-1: "System credential storage facilities need to be used to store sensitive data, such as PII, user credentials or cryptographic keys."
- MSTG-CRYPTO-1: "The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption."
- MSTG-CRYPTO-2: "The app uses proven implementations of cryptographic primitives."
- MSTG-CRYPTO-3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices."
- MSTG-CRYPTO-4: "The app does not use cryptographic protocols or algorithms that are widely considered deprecated for security purposes."
- MSTG-CRYPTO-5: "The app doesn't re-use the same cryptographic key for multiple purposes."
- MSTG-CRYPTO-6: "All random values are generated using a sufficiently secure random number generator."
