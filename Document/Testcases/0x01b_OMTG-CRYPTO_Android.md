### <a name="OMTG-CRYPTO-001"></a>OMTG-CRYPTO-001: Test Key Management Process

#### Overview

The use of a hard-coded or world-readable cryptographic key significantly increases the possibility that encrypted data may be recovered.

#### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

#### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

#### Remediation

If you need to store a key for repeated use, use a mechanism, such as KeyStore<sup>[1]</sup>, that provides a mechanism for long term storage and retrieval of cryptographic keys.

#### References

* [1]: https://developer.android.com/reference/java/security/KeyStore.html

##### OWASP MASVS
- V3.1: "The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption"
- V3.5: "The app doesn't re-use the same cryptographic key for multiple purposes"
- V3.7: "All cryptographic keys are changeable, and are generated or replaced at installation time"

##### OWASP Mobile Top 10
* M6 - Broken Cryptography

##### CWE
* CWE-320: Key Management Errors
* CWE-321: Use of Hard-coded Cryptographic Key

##### Info

* [TBD] TBD

##### Tools
* [QARK](https://github.com/linkedin/qark)
* [Mobile Security Framework](https://github.com/ajinabraham/Mobile-Security-Framework-MobSF)




### <a name="OMTG-CRYPTO-002"></a>OMTG-CRYPTO-002: Test for Use of Custom Encryption Protocols

#### Overview

The use of a non-standard algorithm is dangerous because a determined attacker may be able to break the algorithm and compromise whatever data has been protected. Well-known techniques may exist to break the algorithm.

#### White-box Testing

Carefully inspect all the crypto methods, especially those which are directly applied to the sensitive data. Pay close attention to seemingly standard but modified algorithms. Remember that encoding is not encryption! Any appearance of direct XORing might be a good sign to start digging deeper.

#### Black-box Testing

Although fuzzing of the custom algorithm might work in case of very weak crypto, the recommended approach would be to decompile the APK and inspect the algorithm to see if custom encryption schemes is really the case (see "White-box Testing")

#### Remediation

When there is a need to store or transmit sensitive data, use strong, up-to-date cryptographic algorithms to encrypt that data. Select a well-vetted algorithm that is currently considered to be strong by experts in the field, and use well-tested implementations. As with all cryptographic mechanisms, the source code should be available for analysis.
Do not develop custom or private cryptographic algorithms. They will likely be exposed to attacks that are well-understood by cryptographers. Reverse engineering techniques are mature. If the algorithm can be compromised if attackers find out how it works, then it is especially weak.

##### OWASP MASVS
- V3.2: "The app uses proven implementations of cryptographic primitives"

##### OWASP Mobile Top 10
* M6 - Broken Cryptography

##### CWE
* CWE-327: Use of a Broken or Risky Cryptographic Algorithm



### <a name="OMTG-CRYPTO-003"></a>OMTG-CRYPTO-003: Test for Use of Insecure and/or Deprecated Algorithms

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

#### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

#### Remediation

Periodically ensure that the cryptography has not become obsolete. Some older algorithms, once thought to require a billion years of computing time, can now be broken in days or hours. This includes MD4, MD5, SHA1, DES, and other algorithms that were once regarded as strong. Examples of currently recommended algorithms<sup>[1][2]</sup>:

* Confidentiality: AES-256
* Integrity: SHA-256, SHA-384, SHA-512
* Digital signature: RSA (3072 bits and higher), ECDSA with NIST P-384
* Key establishment: RSA (3072 bits and higher), DH (3072 bits or higher), ECDH with NIST P-384


#### References

* [1]: [Commercial National Security Algorithm Suite and Quantum Computing FAQ](https://cryptome.org/2016/01/CNSA-Suite-and-Quantum-Computing-FAQ.pdf)
* [2]: [NIST Special Publication 800-57](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf)

##### OWASP MASVS
- V3.3: "The app does not use cryptographic protocols or algorithms that are widely considered depreciated"
- V3.4: "Cryptographic modules use parameters that adhere to current industry best practices. This includes key length and modes of operation"

##### OWASP Mobile Top 10
* M6 - Broken Cryptography

##### CWE
* CWE-326: Inadequate Encryption Strength
* CWE-327: Use of a Broken or Risky Cryptographic Algorithm

##### Info

* [TBD] TBD

##### Tools
* [QARK](https://github.com/linkedin/qark)
* [Mobile Security Framework](https://github.com/ajinabraham/Mobile-Security-Framework-MobSF)


### <a name="OMTG-CRYPTO-004"></a>OMTG-CRYPTO-004: Verify that random values are generated using a sufficiently secure random number generator

#### Overview

When software generates predictable values in a context requiring unpredictability, it may be possible for an attacker to guess the next value that will be generated, and use this guess to impersonate another user or access sensitive information.

#### White-box Testing

Identify all the instances of random number generators and look for either custom or known insecure java.util.Random class. This class produces an identical sequence of numbers for each given seed value; consequently, the sequence of numbers is predictable.
Sample weak random generation code:

```
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

#### Black-box Testing

Knowing what type of weak PRNG is used, it can be trivial to write proof-of-concept to generate next random value based on previously observed ones, as it was done for Java Random<sup>[1]</sup>. In case of very weak custom random generators it may be possible to observe the pattern statistically, although the recommended approach would anyway be to decompile the APK and inspect the algorithm (see "White-box Testing")

#### Remediation

Use a well-vetted algorithm that is currently considered to be strong by experts in the field, and select well-tested implementations with adequate length seeds. Prefer the no-argument constructor of SecureRandom that uses the system-specified seed value to generate a 128-byte-long random number<sup>[2]</sup>.
In general, if a pseudo-random number generator is not advertised as being cryptographically secure (e.g. java.util.Random), then it is probably a statistical PRNG and should not be used in security-sensitive contexts.
Pseudo-random number generators can produce predictable numbers if the generator is known and the seed can be guessed<sup>[3]</sup>. A 128-bit seed is a good starting point for producing a "random enough" number.

Sample secure random generation:

```
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

* [1]: [Predicting the next Math.random() in Java](http://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/)
* [2]: [Generation of Strong Random Numbers](https://www.securecoding.cert.org/confluence/display/java/MSC02-J.+Generate+strong+random+numbers)
* [3]: [Proper seeding of SecureRandom](https://www.securecoding.cert.org/confluence/display/java/MSC63-J.+Ensure+that+SecureRandom+is+properly+seeded)

##### OWASP MASVS
- V3.6: "All random values are generated using a sufficiently secure random number generator"

##### OWASP Mobile Top 10
* M6 - Broken Cryptography

##### CWE
* CWE-330: Use of Insufficiently Random Values

##### Tools
* [QARK](https://github.com/linkedin/qark)
