## Testing Cryptography in Android Apps

### Testing for Hardcoded Cryptographic Keys

#### Overview

-- REVIEW --
The use of a hard-coded or world-readable cryptographic key significantly increases the possibility that encrypted data may be recovered. Once it is obtained by an attacker, the task to decrypt the sensitive data becomes trivial, and the initial idea to protect confidentiality fails.

When using symmetric cryptography, the key needs to be stored within the device and it is just a matter of time and effort from the attacker to identify it.

#### Static Analysis

Consider the following scenario: An application is reading and writing to an encrypted database but the decryption is done based on a hardcoded key:

```Java
this.db = localUserSecretStore.getWritableDatabase("SuperPassword123");
```

Since the key is the same for all App installations it is trivial to obtain it. The advantages of having sensitive data encrypted are gone, and there is effectively no benefit in using encryption in this way. Similarly, look for hardcoded API keys / private keys and other valuable pieces. Encoded/encrypted keys is just another attempt to make it harder but not impossible to get the crown jewels.

Let's consider this piece of code:

```Java
//A more complicated effort to store the XOR'ed halves of a key (instead of the key itself)
private static final String[] myCompositeKey = new String[]{
  "oNQavjbaNNSgEqoCkT9Em4imeQQ=","3o8eFOX4ri/F8fgHgiy/BS47"
};
```

Algorithm to decode the original key in this case might look like this<sup>[1]</sup>:

```Java
public void useXorStringHiding(String myHiddenMessage) {
  byte[] xorParts0 = Base64.decode(myCompositeKey[0],0);
  byte[] xorParts1 = Base64.decode(myCompositeKey[1],0);

  byte[] xorKey = new byte[xorParts0.length];
  for(int i = 0; i < xorParts1.length; i++){
    xorKey[i] = (byte) (xorParts0[i] ^ xorParts1[i]);
  }
  HidingUtil.doHiding(myHiddenMessage.getBytes(), xorKey, false);
}
```

#### Dynamic Analysis

Verify common places where secrets are usually hidden:
* resources (typically at res/values/strings.xml)

Example:
```xml
<resources>
    <string name="app_name">SuperApp</string>
    <string name="hello_world">Hello world!</string>
    <string name="action_settings">Settings</string>
    <string name="secret_key">My_S3cr3t_K3Y</string>
  </resources>
```

* build configs, such as in local.properties or gradle.properties

Example:
```
buildTypes {
  debug {
    minifyEnabled true
    buildConfigField "String", "hiddenPassword", "\"${hiddenPassword}\""
  }
}
```

* shared preferences, typically at /data/data/package_name/shared_prefs

#### Remediation

If you need to store a key for repeated use, use a mechanism, such as KeyStore<sup>[2]</sup>, that provides a mechanism for long term storage and retrieval of cryptographic keys.

#### References

##### OWASP Mobile Top 10 2016
* M6 - Broken Cryptography

##### OWASP MASVS
- V3.1: "The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption"
- V3.5: "The app doesn't re-use the same cryptographic key for multiple purposes"

##### CWE
* CWE-320: Key Management Errors
* CWE-321: Use of Hard-coded Cryptographic Key

##### Info

[1] Hiding Passwords in Android - https://github.com/pillfill/hiding-passwords-android/
[2] KeyStore - https://developer.android.com/reference/java/security/KeyStore.html
[3] Hiding Secrets in Android - https://rammic.github.io/2015/07/28/hiding-secrets-in-android-apps/
[4] Securely storing secrets in Android - https://medium.com/@ericfu/securely-storing-secrets-in-an-android-application-501f030ae5a3#.7z5yruotu

##### Tools
* [QARK](https://github.com/linkedin/qark)
* [Mobile Security Framework](https://github.com/ajinabraham/Mobile-Security-Framework-MobSF)

### Verifying the Configuration of Cryptographic Standard Algorithms

#### Overview

-- REVIEW --
Choosing good cryptographic algorithm alone is not enough. Often security of otherwise sound algorithms can be affected if misconfigured. Many previously strong algorithms and their configurations are now considered vulnerable or non-compliant with best practices. It is therefore important to periodically check current best practices and adjust configurations accordingly.  

#### Static Analysis

-- TODO [Describe Static Analysis on Verifying the Configuration of Cryptographic Standard Algorithms : how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Clarify the purpose of "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Develop Static Analysis with source code of "Verifying the Configuration of Cryptographic Standard Algorithms"] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Verifying the Configuration of Cryptographic Standard Algorithms" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

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

##### Tools

-- TODO [Add relevant tools for "Verifying the Configuration of Cryptographic Standard Algorithms"] --
* Enjarify - https://github.com/google/enjarify


### Testing for Insecure and/or Deprecated Cryptographic Algorithms

#### Overview

Many cryptographic algorithms and protocols should not be used because they have been shown to have significant weaknesses or are otherwise insufficient for modern security requirements.

#### Static Analysis

Inspect the source code to identify the instances of cryptographic algorithms throughout the application, and look for known weak ones, such as
* DES
* RC2
* CRC32
* MD4
* MD5
* SHA1 and others.

See "Remediation" section for a basic list of recommended algorithms.

Example initialization of DES algorithm, that is considered weak:
```Java
Cipher cipher = Cipher.getInstance("DES");
```
##### Block cipher encryption modes
Do not use ECB encryption mode, it is basically raw cipher. For each block of input, you encrypt that block and get some output. The problem with this transform is that any resident properties of the plaintext might well show up in the ciphertext – possibly not as clearly – that's what blocks and key schedules are supposed to protect againt, but analyzing the patterns you may be able to deduce properties that you otherwise thought were hidden.

<p align="center">
  <img src="Images/Chapters/0x5e/EncryptionMode.png">
    <br>
    Difference of encryption modes
</p>

#### Dynamic Analysis

-- TODO [Give examples of Dynamic Testing for "Testing for Insecure and/or Deprecated Cryptographic Algorithms"] --

#### Remediation

Periodically ensure that the cryptography has not become obsolete. Some older algorithms, once thought to require a billion years of computing time, can now be broken in days or hours. This includes MD4, MD5, SHA1, DES, and other algorithms that were once considered as strong. Examples of currently recommended algorithms<sup>[1][2]</sup>:

* Confidentiality: AES-256
* Integrity: SHA-256, SHA-384, SHA-512
* Digital signature: RSA (3072 bits and higher), ECDSA with NIST P-384
* Key establishment: RSA (3072 bits and higher), DH (3072 bits or higher), ECDH with NIST P-384

#### References

##### OWASP Mobile Top 10
* M6 - Broken Cryptography

##### OWASP MASVS
- V3.3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices"
- V3.4: "The app does not use cryptographic protocols or algorithms that are widely considered depreciated for security purposes"

##### CWE
* CWE-326: Inadequate Encryption Strength
* CWE-327: Use of a Broken or Risky Cryptographic Algorithm

##### Info
[1] Commercial National Security Algorithm Suite and Quantum Computing FAQ - https://cryptome.org/2016/01/CNSA-Suite-and-Quantum-Computing-FAQ.pdf
[2] NIST Special Publication 800-57 - http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf
[3] Security "Crypto" provider deprecated in Android N -  https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html

##### Tools
* QARK - https://github.com/linkedin/qark
* Mobile Security Framework - https://github.com/ajinabraham/Mobile-Security-Framework-MobSF



### Testing Random Number Generation

#### Overview

When software generates predictable values in a context requiring unpredictability, it may be possible for an attacker to guess the next value that will be generated, and use this guess to impersonate another user or access sensitive information.

#### Static Analysis

Identify all the instances of random number generators and look for either custom or known insecure java.util.Random class. This class produces an identical sequence of numbers for each given seed value; consequently, the sequence of numbers is predictable.
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

Use a well-vetted algorithm that is currently considered to be strong by experts in the field, and select well-tested implementations with adequate length seeds. Prefer the no-argument constructor of SecureRandom that uses the system-specified seed value to generate a 128-byte-long random number<sup>[2]</sup>.
In general, if a PRNG is not advertised as being cryptographically secure (e.g. java.util.Random), then it is probably a statistical PRNG and should not be used in security-sensitive contexts.
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
[1] Predicting the next Math.random() in Java - http://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/
[2] Generation of Strong Random Numbers - https://www.securecoding.cert.org/confluence/display/java/MSC02-J.+Generate+strong+random+numbers
[3] Proper seeding of SecureRandom - https://www.securecoding.cert.org/confluence/display/java/MSC63-J.+Ensure+that+SecureRandom+is+properly+seeded

##### Tools
* QARK - https://github.com/linkedin/qark
