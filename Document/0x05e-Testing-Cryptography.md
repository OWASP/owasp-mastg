## Android Cryptographic APIs

In the chapter [Cryptography for Mobile Apps](0x04g-Testing-Cryptography.md), we introduced general cryptography best practices and described typical flaws that can occur when cryptography is used incorrectly in mobile apps. In this chapter, we'll go into more detail on Android's cryptography APIs. We'll show how identify uses of those APIs in the source code and how to interpret the configuration. When reviewing code, make sure to compare the cryptographic parameters used with the current best practices linked from this guide.

### Testing the Configuration of Cryptographic Standard Algorithms (MSTG-CRYPTO-2, MSTG-CRYPTO-3 and MSTG-CRYPTO-4)

#### Overview

Android cryptography APIs are based on the Java Cryptography Architecture (JCA). JCA separates the interfaces and implementation, making it possible to include several [security providers](https://developer.android.com/reference/java/security/Provider.html "Android Security Providers") that can implement sets of cryptographic algorithms. Most of the JCA interfaces and classes are defined in the `java.security.*` and `javax.crypto.*` packages. In addition, there are Android specific packages `android.security.*` and `android.security.keystore.*`.

The list of providers included in Android varies between versions of Android and the OEM-specific builds. Some provider implementations in older versions are now known to be less secure or vulnerable. Thus, Android applications should not only choose the correct algorithms and provide good configuration, in some cases they should also pay attention to the strength of the implementations in the legacy providers.

You can list the set of existing providers as follows:

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

Below you can find the output of a running Android 4.4 in an emulator with Google Play APIs, after the security provider has been patched:

```text
provider: GmsCore_OpenSSL1.0 (Android's OpenSSL-backed security provider)
provider: AndroidOpenSSL1.0 (Android's OpenSSL-backed security provider)
provider: DRLCertFactory1.0 (ASN.1, DER, PkiPath, PKCS7)
provider: BC1.49 (BouncyCastle Security Provider v1.49)
provider: Crypto1.0 (HARMONY (SHA1 digest; SecureRandom; SHA1withDSA signature))
provider: HarmonyJSSE1.0 (Harmony JSSE Provider)
provider: AndroidKeyStore1.0 (Android AndroidKeyStore security provider)
```

For some applications that support older versions of Android (e.g.: only used Pre Android Nougat), bundling an up-to-date library may be the only option. Spongy Castle (a repackaged version of Bouncy Castle) is a common choice in these situations. Repackaging is necessary because Bouncy Castle is included in the Android SDK. The latest version of [Spongy Castle](https://rtyley.github.io/spongycastle/ "Spongy Castle") likely fixes issues encountered in the earlier versions of [Bouncy Castle](https://www.cvedetails.com/vulnerability-list/vendor_id-7637/Bouncycastle.html "CVE Details Bouncy Castle") that were included in Android. Note that the Bouncy Castle libraries packed with Android are often not as complete as their counterparts from the [legion of the Bouncy Castle](https://www.bouncycastle.org/java.html "Bouncy Castle in Java"). Lastly: bear in mind that packing large libraries such as Spongy Castle will often lead to a multidexed Android application.

Apps that target modern API levels, went through the following changes:

- For Android Nougat (7.0) and above [the Android Developer blog shows that](https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html "Security provider Crypto deprecated in Andorid N"):
  - It is recommended to stop specifying a security provider. Instead, always use a patched security provider.
  - The support for the `Crypto` provider has dropped and the provider is deprecated.
  - There is no longer support for `SHA1PRNG` for secure random, but instead the runtime provides an instance of `OpenSSLRandom`.
- For Android Oreo (8.1) and above the [Developer Documentation](https://developer.android.com/about/versions/oreo/android-8.1 "Cryptography updates") shows that:
  - Conscrypt, known as `AndroidOpenSSL`, is preferred above using Bouncy Castle and it has new implementations: `AlgorithmParameters:GCM` , `KeyGenerator:AES`, `KeyGenerator:DESEDE`, `KeyGenerator:HMACMD5`, `KeyGenerator:HMACSHA1`, `KeyGenerator:HMACSHA224`, `KeyGenerator:HMACSHA256`, `KeyGenerator:HMACSHA384`, `KeyGenerator:HMACSHA512`, `SecretKeyFactory:DESEDE`, and `Signature:NONEWITHECDSA`.
  - You should not use the `IvParameterSpec.class` anymore for GCM, but use the `GCMParameterSpec.class` instead.
  - Sockets have changed from `OpenSSLSocketImpl` to `ConscryptFileDescriptorSocket`, and `ConscryptEngineSocket`.
  - `SSLSession` with null parameters give an NullPointerException.
  - You need to have large enough arrays as input bytes for generating a key otherwise, an InvalidKeySpecException is thrown.
  - If a Socket read is interrupted, you get an `SocketException`.
- For Android Pie (9.0) and above the [Android Developer Blog](https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html "Cryptography Changes in Android P
") shows even more aggressive changes:
  - You get a warning if you still specify a provider using the `getInstance()` method and you target any API below P. If you target P or above, you get an error.
  - The `Crypto` provider is now removed. Calling it will result in a `NoSuchProviderException`.

Android SDK provides mechanisms for specifying secure key generation and use. Android 6.0 (Marshmallow, API 23) introduced the `KeyGenParameterSpec` class that can be used to ensure the correct key usage in the application.

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

The `KeyGenParameterSpec` indicates that the key can be used for encryption and decryption, but not for other purposes, such as signing or verifying. It further specifies the block mode (CBC), padding (PKCS #7), and explicitly specifies that randomized encryption is required (this is the default.) `"AndroidKeyStore"` is the name of the cryptographic service provider used in this example. This will automatically ensure that the keys are stored in the `AndroidKeyStore` which is beneficiary for the protection of the key.

GCM is another AES block mode that provides additional security benefits over other, older modes. In addition to being cryptographically more secure, it also provides authentication. When using CBC (and other modes), authentication would need to be performed separately, using HMACs (see the Reverse Engineering chapter). Note that GCM is the only mode of AES that [does not support paddings](https://developer.android.com/training/articles/keystore.html#SupportedCiphers "Supported Ciphers in AndroidKeyStore").

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

Prior to Android 6.0, AES key generation was not supported. As a result, many implementations chose to use RSA and generated a public-private key pair for asymmetric encryption using `KeyPairGeneratorSpec` or used `SecureRandom` to generate AES keys.

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

Note: there is a widespread false believe that the NDK should be used to hide cryptographic operations and hardcoded keys. However, using this mechanisms is not effective. Attackers can still use tools to find the mechanism used and make dumps of the key in memory. Next, the control flow can be analyzed with IDA(pro). From Android Nougat onward, it is not allowed to use private APIs, instead: public APIs need to be called, which further impacts the effectiveness of hiding it away as described in the [Android Developers Blog](https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html "Android changes for NDK developers")

#### Static Analysis

Locate uses of the cryptographic primitives in code. Some of the most frequently used classes and interfaces:

- `Cipher`
- `Mac`
- `MessageDigest`
- `Signature`
- `Key`, `PrivateKey`, `PublicKey`, `SecretKey`
- And a few others in the `java.security.*` and `javax.crypto.*` packages.

Ensure that the best practices outlined in the "Cryptography for Mobile Apps" chapter are followed. Verify that the configuration of cryptographic algorithms used are aligned with best practices from [NIST](https://www.keylength.com/en/4/ "NIST recommendations - 2016") and [BSI](https://www.keylength.com/en/8/ "BSI recommendations - 2017") and are considered as strong. Make sure that `SHA1PRNG` is no longer used as it is not cryptographically secure.
Lastly, make sure that keys are not hardcoded in native code and that no insecure mechanisms are used at this level.

### Testing Random Number Generation (MSTG-CRYPTO-6)

#### Overview

Cryptography requires secure pseudo random number generation (PRNG). Standard Java classes do not provide sufficient randomness and in fact may make it possible for an attacker to guess the next value that will be generated, and use this guess to impersonate another user or access sensitive information.

In general, `SecureRandom` should be used. However, if the Android versions below KitKat are supported, additional care needs to be taken in order to work around the bug in Jelly Bean (Android 4.1-4.3) versions that [failed to properly initialize the PRNG](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html "Some SecureRandom Thoughts").

Most developers should instantiate `SecureRandom` via the default constructor without any arguments. Other constructors are for more advanced uses and, if used incorrectly, can lead to decreased randomness and security. The PRNG provider backing `SecureRandom` uses the `/dev/urandom` device file as the source of randomness by default [#nelenkov].

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

If you want to test for randomness, you can try to capture a large set of numbers and check with the Burp's [sequencer](https://portswigger.net/burp/documentation/desktop/tools/sequencer "Burp's Sequencer") to see how good the quality of the randomness is.

### Testing Key Management (MSTG-STORAGE-1, MSTG-CRYPTO-1 and MSTG-CRYPTO-5)

#### Overview

In this section we will discuss different ways to store cryptographic keys and how to test for them. We discuss the most secure way, down to the less secure way of generating and storing key material.

The most secure way of handling key material, is simply never storing it on the device. This means that the user should be prompted to input a passphrase every time the application needs to perform a cryptographic operation. Although this is not the ideal implementation from a user experience point of view, it is however the most secure way of handling key material. The reason is because key material will only be available in an array in memory while it is being used. Once the key is not needed anymore, the array can be zeroed out. This minimizes the attack window as good as possible. No key material touches the filesystem and no passphrase is stored. However, note that some ciphers do not properly clean up their byte-arrays. For instance, the AES Cipher in BouncyCastle does not always clean up its latest working key. Next, BigInteger based keys (e.g. private keys) cannot be removed from the heap nor zeroed out just like that. Last, take care when trying to zero out the key. See section "Testing Data Storage for Android" on how to make sure that the key its contents indeed are zeroed out.

A symmetric encryption key can be generated from the passphrase by using the Password Based Key Derivation Function version 2 (PBKDF2). This cryptographic protocol is designed to generate secure and non brute-forceable keys. The code listing below illustrates how to generate a strong encryption key based on a password.

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

The above method requires a character array containing the password and the needed keylength in bits, for instance a 128 or 256-bit AES key. We define an iteration count of 10000 rounds which will be used by the PBKDF2 algorithm. This significantly increases the workload for a bruteforce attack. We define the salt size equal to the key length, we divide by 8 to take care of the bit to byte conversion. We use the `SecureRandom` class to randomly generate a salt. Obviously, the salt is something you want to keep constant to ensure the same encryption key is generated time after time for the same supplied password. Note that you can store the salt privately in `SharedPreferences`. It is recommended to exclude the salt from the Android backup mechanism to prevent synchronization in case of higher risk data. See "testing android storage" for more details.
Note that if you take a rooted device, or unpatched device, or a patched (e.g. repackaged) application into account as a threat to the data, it might be better to encrypt the salt with a key in the `AndroidKeystore`. Afterwards the Password-based Encryption (PBE) key is generated using the recommended `PBKDF2WithHmacSHA1` algorithm till API version 26. From there on it is best to use `PBKDF2withHmacSHA256`, which will end up with a different keysize.

Now, it is clear that regularly prompting the user for its passphrase is not something that works for every application. In that case make sure you use the [Android KeyStore API](https://developer.android.com/reference/java/security/KeyStore.html "Android AndroidKeyStore API"). This API has been specifically developed to provide a secure storage for key material. Only your application has access to the keys that it generates. Starting from Android 6.0 it is also enforced that the AndroidKeyStore is hardware-backed in case a fingerprint sensor is present. This means a dedicated cryptography chip or trusted platform module (TPM) is being used to secure the key material.

However, be aware that the `AndroidKeyStore` API has been changed significantly throughout various versions of Android. In earlier versions the `AndroidKeyStore` API only supported storing public/private key pairs (e.g., RSA). Symmetric key support has only been added since API level 23. As a result, a developer needs to take care when he wants to securely store symmetric keys on different Android API levels. In order to securely store symmetric keys, on devices running on Android API level 22 or lower, we need to generate a public/private key pair. We encrypt the symmetric key using the public key and store the private key in the `AndroidKeyStore`. The encrypted symmetric key can now be safely stored in the `SharedPreferences`. Whenever we need the symmetric key, the application retrieves the private key from the `AndroidKeyStore` and decrypts the symmetric key.
When keys are generated and used within the `AndroidKeyStore` and the `KeyInfo.isinsideSecureHardware()` returns true, then we know that you cannot just dump the keys nor monitor its cryptographic operations. It becomes debatable what will be eventually more safe: using `PBKDF2withHmacSHA256` to generate a key that is still in reachable dumpable memory, or using the `AndroidKeyStore` for which the keys might never get into memory. With Android Pie we see that additional security enhancements have been implemented in order to separate the TEE from the `AndroidKeyStore` which make it favorable over using `PBKDF2withHmacSHA256`. However, more testing & investigating will take place on that subject in the near future.

#### Secure key import into Keystore

Android Pie adds the ability to import keys securely into the `AndroidKeystore`. First `AndroidKeystore` generates a key pair using `PURPOSE_WRAP_KEY` which should also be protected with an attestation certficate, this pair aims to protect the Keys being imported to `AndroidKeystore`. The encypted keys are generated as ASN.1-encoded message in the `SecureKeyWrapper` format which also contains a description of the ways the imported key is allowed to be used. The keys are then decrypted inside the `AndroidKeystore` hardware belonging to the specific device that generated the wrapping key so they never appear as plaintext in the device's host memory.

<img src="Images/Chapters/0x5e/Android9_secure_key_import_to_keystore.png" alt="Secure key import into Keystore" width="500">

```java
KeyDescription ::= SEQUENCE {
    keyFormat INTEGER,
    authorizationList AuthorizationList
}

SecureKeyWrapper ::= SEQUENCE {
    wrapperFormatVersion INTEGER,
    encryptedTransportKey OCTET_STRING,
    initializationVector OCTET_STRING,
    keyDescription KeyDescription,
    secureKey OCTET_STRING,
    tag OCTET_STRING
}
```

The code above present the different parameters to be set when generating the encrypted keys in the SecureKeyWrapper format. Check the Android documentation on [WrappedKeyEntry](https://developer.android.com/reference/android/security/keystore/WrappedKeyEntry) for more details.

When defining the KeyDescription AuthorizationList, the following parameters will affect the encrypted keys security:

- The `algorithm` parameter Specifies the cryptographic algorithm with which the key is used
- The `keySize` parameter Specifies the size, in bits, of the key, measuring in the normal way for the key's algorithm
- The `digest` parameter Specifies the digest algorithms that may be used with the key to perform signing and verification operations

#### Key Decryption only on Unlocked Devices

For more security Android pie introduces the `unlockedDeviceRequied` flag. By passing `true` to the `setUnlockedDeviceRequired()` method the app prevents its keys stored in `AndroidKeystore` from being decrypted when the device is locked, and it requires the screen to be unlocked before allowing decryption.

#### StrongBox Hardware Security Module

Devices running Android 9 and higher can have a `StrongBox Keymaster`, an implementation of the Keymaster HAL that resides in a hardware security module which has its own CPU, Secure storage, a true random number generator and a mechanism to resist package tampering. To use this feature, `true` must be passed to the `setIsStrongBoxBacked()` method in either the `KeyGenParameterSpec.Builder` class or the `KeyProtection.Builder` class when generating or importing keys using `AndroidKeystore`. To make sure that StrongBox is used during runtime check that `isInsideSecureHardware` returns `true` and that the system does not throw `StrongBoxUnavailableException` which get thrown if the StrongBox Keymaster isn't available for the given algorithm and key size associated with a key.

#### Key Use Authorizations

To mitigate unauthorized use of keys on the Android device, Android KeyStore lets apps specify authorized uses of their keys when generating or importing the keys. Once made, authorizations cannot be changed.

Another API offered by Android is the `KeyChain`, which provides access to private keys and their corresponding certificate chains in credential storage, which is often not used due to the interaction necessary and the shared nature of the Keychain. See the [Developer Documentation](https://developer.android.com/reference/android/security/KeyChain "Keychain") for more details.

A slightly less secure way of storing encryption keys, is in the SharedPreferences of Android. When [SharedPreferences](https://developer.android.com/reference/android/content/SharedPreferences.html "Android SharedPreference API") are initialized in [MODE_PRIVATE](https://developer.android.com/reference/android/content/Context.html#MODE_PRIVATE "MODE_PRIVATE"), the file is only readable by the application that created it. However, on rooted devices any other application with root access can simply read the SharedPreference file of other apps, it does not matter whether `MODE_PRIVATE` has been used or not. This is not the case for the AndroidKeyStore. Since AndroidKeyStore access is managed on kernel level, which needs considerably more work and skill to bypass without the AndroidKeyStore clearing or destroying the keys.

The last three options are to use hardcoded encryption keys in the source code, having a predictable key derivation function based on stable attributes, and storing generated keys in public places like `/sdcard/`. Obviously, hardcoded encryption keys are not the way to go. This means every instance of the application uses the same encryption key. An attacker needs only to do the work once, to extract the key from the source code - whether stored natively or in Java/Kotlin. Consequently, he can decrypt any other data that he can obtain which was encrypted by the application.
Next, when you have a predictable key derivation function based on identifiers which are accessible to other applications, the attacker only needs to find the KDF and apply it to the device in order to find the key. Lastly, storing encryption keys publicly also is highly discouraged as other applications can have permission to read the public partition and steal the keys.

#### Static Analysis

Locate uses of the cryptographic primitives in the code. Some of the most frequently used classes and interfaces:

- `Cipher`
- `Mac`
- `MessageDigest`
- `Signature`
- `AndroidKeyStore`
- `Key`, `PrivateKey`, `PublicKey`, `SecretKeySpec`, `KeyInfo`
- And a few others in the `java.security.*` and `javax.crypto.*` packages.

As an example we illustrate how to locate the use of a hardcoded encryption key. First disassemble the DEX bytecode to a collection of Smali bytecode files using ```Baksmali```.

```shell
$ baksmali d file.apk -o smali_output/
```

Now that we have a collection of Smali bytecode files, we can search the files for the usage of the ```SecretKeySpec``` class. We do this by simply recursively grepping on the Smali source code we just obtained. Please note that class descriptors in Smali start with `L` and end with `;`:

```shell
$ grep -r "Ljavax\crypto\spec\SecretKeySpec;"
```

This will highlight all the classes that use the `SecretKeySpec` class, we now examine all the highlighted files and trace which bytes are used to pass the key material. The figure below shows the result of performing this assessment on a production ready application. For sake of readability we have reverse engineered the DEX bytecode to Java code. We can clearly locate the use of a static encryption key that is hardcoded and initialized in the static byte array `Encrypt.keyBytes`.

![Use of a static encryption key in a production ready application.](Images/Chapters/0x5e/static_encryption_key.png).

When you have access to the source code, check at least for the following:

- Check which mechanism is used to store a key: prefer the `AndroidKeyStore` over all other solutions.
- Check if defense in depth mechanisms are used to ensure usage of a TEE. For instance: is temporal validity enforced? Is hardware security usage evaluated by the code? See the [KeyInfo documentation](https://developer.android.com/reference/android/security/keystore/KeyInfo "KeyInfo") for more details.
- In case of whitebox cryptography solutions: study their effectiveness or consult a specialist in that area.
- Take special care on verifying the purposes of the keys, for instance:
  - make sure that for asymmetric encryption, the public key is not used for signing and the private key for encryption.
  - make sure that symmetric keys are not reused for multiple purposes. A new symmetric key should be generated if it's used in a different context.

#### Dynamic Analysis

Hook cryptographic methods and analyze the keys that are being used. Monitor file system access while cryptographic operations are being performed to assess where key material is written to or read from.

### References

- [#nelenkov] - N. Elenkov, Android Security Internals, No Starch Press, 2014, Chapter 5.

#### Cryptography references

- Android Developer blog: Crypto provider deprecated - <https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html>
- Android Developer blog: cryptography changes in android P - <https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html>
- Ida Pro - <https://www.hex-rays.com/products/ida/>
- Android Developer blog: changes for NDK developers - <https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html>
- security providers -  <https://developer.android.com/reference/java/security/Provider.html>
- Spongy Castle  - <https://rtyley.github.io/spongycastle/>
- Legion of the Bouncy Castle - <https://www.bouncycastle.org/java.html>
- Android Developer documentation - <https://developer.android.com/guide>
- NIST keylength recommendations - <https://www.keylength.com/en/4/>
- BSI recommendations - 2017 - <https://www.keylength.com/en/8/>

#### SecureRandom references

- Proper seeding of SecureRandom - <https://www.securecoding.cert.org/confluence/display/java/MSC63-J.+Ensure+that+SecureRandom+is+properly+seeded>
- Burpproxy its Sequencer - <https://portswigger.net/burp/documentation/desktop/tools/sequencer>

#### Testing Key Management references

- Android KeyStore API - <https://developer.android.com/reference/java/security/KeyStore.html>
- Android Keychain API - <https://developer.android.com/reference/android/security/KeyChain>
- SharedPreferences - <https://developer.android.com/reference/android/content/SharedPreferences.html>
- KeyInfo documentation - <https://developer.android.com/reference/android/security/keystore/KeyInfo>
- Android Pie features and APIs - <https://developer.android.com/about/versions/pie/android-9.0#secure-key-import>
- Android Keystore system - <https://developer.android.com/training/articles/keystore#java>

##### OWASP Mobile Top 10 2016

- M5 - Insufficient Cryptography - <https://www.owasp.org/index.php/Mobile_Top_10_2016-M5-Insufficient_Cryptography>

##### OWASP MASVS

- MSTG-STORAGE-1: "System credential storage facilities are used appropriately to store sensitive data, such as user credentials or cryptographic keys."
- MSTG-CRYPTO-1: "The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption."
- MSTG-CRYPTO-2: "The app uses proven implementations of cryptographic primitives."
- MSTG-CRYPTO-3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices."
- MSTG-CRYPTO-4: "The app does not use cryptographic protocols or algorithms that are widely considered depreciated for security purposes."
- MSTG-CRYPTO-5: "The app doesn't reuse the same cryptographic key for multiple purposes."
- MSTG-CRYPTO-6: "All random values are generated using a sufficiently secure random number generator."

##### CWE

- CWE-321 - Use of Hard-coded Cryptographic Key
- CWE-326 - Inadequate Encryption Strength
- CWE-330 - Use of Insufficiently Random Values
