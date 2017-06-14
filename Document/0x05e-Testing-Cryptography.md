## Testing Cryptography in Android Apps

### Verifying the Configuration of Cryptographic Standard Algorithms

#### Overview

A general rule in app development is that one should never attempt to invent their own cryptography. In mobile apps in particular, any form of crypto should be implemented using existing, robust implementations. In 99% of cases, this simply means using the data storage APIs and cryptographic libraries that come with the mobile OS.

Android developers don't need to bother much with the intricate details of cryptography most of the time. However, even when using standard algorithms can be affected if misconfigured. 

Android SDK provides mechanisms for specifying secure key generation and use. Android 6.0 (Marshmallow, API 23) introduced the `KeyGenParameterSpec` class that can be used to ensure the correct key usage in the application.

Here's an example of using AES:

```
String keyAlias = "MySecretKey";
String ANDROID_KEY_STORE = "AndroidKeyStore";

KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(keyAlias,
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)
        .build();

KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
        ANDROID_KEY_STORE);
keyGenerator.init(keyGenParameterSpec);

SecretKey secretKey = keyGenerator.generateKey();
```

The `KeyGenParameterSpec` indicates that the key can be used for encryption and decryption, but not for other purposes, such as signing or verifying. It further specifies the block mode (GCM), padding (none), and explicitly specifies that randomized encryption is required (this is the default.) Note that GCM is the only mode of AES that does not support paddings. For all other modes, padding should be used, e.g., `PKCS5Padding`.<sup>[3], [5]</sup>

Attempting to use the generated key in violation of the above spec would result in a security exception.

Here's an example of using that key correctly:

```
String AES_MODE = KeyProperties.KEY_ALGORITHM_AES
        + "/" + KeyProperties.BLOCK_MODE_GCM
        + "/" + KeyProperties.ENCRYPTION_PADDING_NONE;
KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);

Key key = keyStore.getKey(keyAlias, null);

Cipher cipher = Cipher.getInstance(AES_MODE);
cipher.init(Cipher.ENCRYPT_MODE, key);

byte[] encryptedBytes = cipher.doFinal(input);
byte[] iv = cipher.getIV();
```

Since the IV (initialization vector) is randomly generated each time, it should be saved along with the cipher text (`encryptedBytes`) in order to decrypt it later.

Prior to Android 6.0, AES key generation was not supported. As a result, many implementations used `SecureRandom` to generate AES keys.

-- TODO Add the pre-Marshmallow example --



#### Static Analysis

Locate uses of the cryptographic primitives in code. Some of the most frequently used classes and interfaces:

* `Cipher`
* `Mac`
* `MessageDigest`
* `Signature`
* `Key`, `PrivateKey`, `PublicKey`, `SecretKey`
* And a few others in the `java.security.*` and `javax.crypto.*` packages.

Ensure that the best practices outlined in the [Cryptography for Mobile Apps](#cryptography-for-mobile-apps) chapter are followed.

#### Remediation

See the Remediation section in the [Cryptography for Mobile Apps](#cryptography-for-mobile-apps) chapter.

-- REVIEW --

Use cryptographic algorithm configurations that are currently considered strong, such those from NIST<sup>1</sup> and BSI<sup>2</sup> recommendations.


#### References

##### OWASP Mobile Top 10

* M6 - Broken Cryptography

##### OWASP MASVS

-- REVIEW --

- V3.3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices"

##### CWE

-- REVIEW --

* CWE-326: Inadequate Encryption Strength


##### Info

-- REVIEW --

- [1] NIST recommendations (2016) - https://www.keylength.com/en/4/
- [2] BSI recommendations (2017) - https://www.keylength.com/en/8/
- [3] Supported Ciphers in KeyStore - https://developer.android.com/training/articles/keystore.html#SupportedCiphers
- [4] Credential storage enhancements in Android 4.3 (August 21, 2013) - https://nelenkov.blogspot.co.uk/2013/08/credential-storage-enhancements-android-43.html


### Testing Random Number Generation

#### Overview

Cryptography requires secure pseudo random number generation (PRNG). Standard Java classes do not provide sufficient randomness and in fact may make it possible for an attacker to guess the next value that will be generated, and use this guess to impersonate another user or access sensitive information.

In general, `SecureRandom` should be used. However, if the Android versions below KitKat are supported, additional care needs to be taken in order to work around the bug in Jelly Bean (Android 4.1-4.3) versions that failed to properly initialize the PRNG<sup>[4]</sup>.

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

#### Dynamic Analysis

Once an attacker is knowing what type of weak pseudo-random number generator (PRNG) is used, it can be trivial to write proof-of-concept to generate the next random value based on previously observed ones, as it was done for Java Random<sup>[1]</sup>. In case of very weak custom random generators it may be possible to observe the pattern statistically. Although the recommended approach would anyway be to decompile the APK and inspect the algorithm (see Static Analysis).

#### Remediation

Use a well-vetted algorithm that is currently considered to be strong by experts in the field, and select well-tested implementations with adequate length seeds. Prefer the no-argument constructor of `SecureRandom` that uses the system-specified seed value to generate a 128-byte-long random number<sup>[2]</sup>.
In general, if a PRNG is not advertised as being cryptographically secure (e.g. `java.util.Random`), then it is probably a statistical PRNG and should not be used in security-sensitive contexts.
Pseudo-random number generators can produce predictable numbers if the generator is known and the seed can be guessed<sup>[3]</sup>. A 128-bit seed is a good starting point for producing a "random enough" number.

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

#### References

##### OWASP MASVS
- V3.6: "All random values are generated using a sufficiently secure random number generator"

##### OWASP Mobile Top 10 2016
* M6 - Broken Cryptography

##### CWE
* CWE-330: Use of Insufficiently Random Values

##### Info
- [1] Predicting the next Math.random() in Java - http://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/
- [2] Generation of Strong Random Numbers - https://www.securecoding.cert.org/confluence/display/java/MSC02-J.+Generate+strong+random+numbers
- [3] Proper seeding of SecureRandom - https://www.securecoding.cert.org/confluence/display/java/MSC63-J.+Ensure+that+SecureRandom+is+properly+seeded
- [4] Some SecureRandom Thoughts - https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html

