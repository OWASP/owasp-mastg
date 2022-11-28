# Mobile App Cryptography

## Overview

Cryptography plays an especially important role in securing the user's data - even more so in a mobile environment, where attackers having physical access to the user's device is a likely scenario. This chapter provides an outline of cryptographic concepts and best practices relevant to mobile apps. These best practices are valid independently of the mobile operating system.

The goal of cryptography is to provide constant confidentiality, data integrity, and authenticity, even in the face of an attack.

- **Confidentiality** involves ensuring data secrecy through the use of encryption.
- **Data integrity** ensures that data has not been modified in an unauthorized manner since it was created, transmitted, or stored. This is usually achieved using message authentication codes or digital signatures.
- **Authenticity** ensures that the data comes from a trusted source. Commonly, digital signatures, message authentication codes and some key-agreement techniques are used to provide authentication.

These properties are defined by the NIST ["Recommendation for Key Management: Part 1 – General (NIST SP 800-57 Part 1 Rev.5)"](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf) as "Security Services" along with authorization and non-repudiation. In many cases, a combination of security services is desired. For example: a digital signature algorithm can provide authenticity, integrity and non-repudiation.

This chapter focuses on following best practices for the use of cryptography in mobile apps. This includes:

- only use approved [cryptographic algorithms](#cryptographic-algorithms) (don't roll your own crypto; assures crypto strength)
- use validated [cryptography implementations](#cryptography-implementations) (assurance correctness for cryptography modules)
- use the algorithms properly (avoid [common configuration issues](#common-cryptography-configuration-issues))
- [manage keys](#key-management) properly (generate with proper strength, protect in storage or transport, etc.)

## Cryptographic Algorithms

We will define Cryptographic Algorithms based on the definitions from the NIST ["Guideline for Using
Cryptographic Standards in the Federal Government: Cryptographic Mechanisms (NIST SP 800-175B Rev.1)"](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175Br1.pdf).

### Hash Algorithms

A hash algorithm (or hash function) is a cryptographic primitive algorithm consisting of a one-way function that takes an input of arbitrary length and outputs a value with a predetermined length called hash value or message digest. It's easy to compute the hash from the input, but extremely difficult to determine the original input. Additionally, the hash will completely change when even a single bit of the input changes.

Hash functions are used for integrity verification, but don't provide an authenticity guarantee. They are usually used in higher-level algorithms, including:

- Keyed-hash message authentication code algorithms
- Digital signature algorithms
- Key derivation functions (e.g., for key establishment)
- Random bit generators

### Symmetric-Key Algorithms

Symmetric-key algorithms (sometimes known as secret-key algorithms) transform data in a way that is fundamentally difficult to undo without knowledge of a secret key. The key is “symmetric” because the same key is used for a cryptographic operation and its inverse (e.g., for both encryption and decryption)

Symmetric-key algorithms are used for:

- Encryption to provide data confidentiality
- Authentication to provide assurance of data integrity and the source of the data
- Key derivation
- Key wrapping
- Random bit generation

A common use case is **encryption**, the key used to encrypt data is also used to decrypt the encrypted data. In the case of encryption, the original data is called the plaintext, while the encrypted form of the data is called the ciphertext. The key must be kept secret if the data is to remain protected.

Symmetric encryption is fast and suitable for bulk data processing. Since everybody who has access to the key is able to decrypt the encrypted content, this method requires careful key management and centralized control over key distribution.

#### Block Cipher Algorithms

Encryption algorithms converts plaintext data into cipher text that conceals the original content. Plaintext data can be restored from the cipher text through decryption. Encryption can be **symmetric** (encryption/decryption with same secret-key) or **asymmetric** (encryption/decryption using a public and private key pair). In general, encryption operations do not protect integrity, but some symmetric encryption modes also feature that protection.

With a symmetric-key block cipher algorithm, the same input block will always produce the same output block when the same key is used. If the multiple blocks in a typical message are encrypted separately, an adversary can easily substitute individual blocks, possibly without detection. Furthermore, certain kinds of data patterns in the plaintext, such as repeated blocks, would be apparent in the ciphertext. To counteract these properties, **modes of operation** have been specified for using a block cipher algorithm.

These modes combine the cryptographic primitive algorithm with a symmetric key and **variable starting values (commonly known as initialization vectors)** to provide some cryptographic service (e.g., the encryption of a message or the generation of a message authentication code).

#### Hash-based Symmetric-key Algorithms

**Message Authentication Codes** (MACs) combine other cryptographic mechanisms (such as symmetric encryption or hashes) with secret keys to provide both integrity and authenticity protection. However, in order to verify a MAC, multiple entities have to share the same secret key and any of those entities can generate a valid MAC. HMACs, the most commonly used type of MAC, rely on hashing as the underlying cryptographic primitive. The full name of an HMAC algorithm usually includes the underlying hash function's type (for example, HMAC-SHA256 uses the SHA-256 hash function).

### Asymmetric-Key Algorithms

Asymmetric-key algorithms, commonly known as public-key algorithms, use two related keys (i.e., a key pair) to perform their functions: a _public key_ which may be known by anyone and _private key_ which should be under the sole control of the entity that “owns” the key pair. Even though this keys are related, knowledge of the public key cannot be used to determine the private key.

In contrast to symmetric-key algorithms, one of the keys of the key pair is used to apply cryptographic protection, and the other key is used to remove or verify that protection. For example:

- a digital signature is computed using a **private** key, and the signature is verified using the public key.
- asymmetric encryption is performed using the public key, and the decryption is performed using the **private** key.

Asymmetric algorithms are used, for example, for:

- Digital signatures to provide source, identity, and integrity authentication services.
- Key-Establishment using key-agreement and key-transport algorithms.

#### Digital Signature Algorithms

Digital signatures combine asymmetric cryptography with hash functions to provide integrity and authenticity by encrypting the hash of the message with the private key. However, unlike MACs, signatures also provide non-repudiation property as the private key should remain unique to the data signer.

They can be computed on data of any length (up to a limit that is determined by the hash function).

#### Key-Establishment Schemes

Key establishment is the means by which keys are generated and provided to the entities that are authorized to use them. Scenarios for which key establishment could be performed include the following.

- Key Generation
- Key Derivation
- Key Agreement
- Key Transport/Distribution
- Key Wrapping

##### Key Derivation

Key Derivation is implemented via **Key Derivation Functions (KDFs)** that generates keys from secret information, which could be a key that is already shared between the entities (i.e., a pre-shared key) or a shared secret that is derived during a key-agreement scheme.

Keys can also be derived from passwords. However, due to the ease of guessing most passwords, keys
derived in this manner are usually not suitable for most applications. However, [SP 800-132](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
specifies a family of functions, called **Password-Based Key Derivation Functions (PBKDF)** that can be used to derive keying material from a password for electronic storage applications (e.g., when encrypting an entire disk drive).

##### Key Agreement

Key Agreement is a key-establishment procedure in which the resultant keying material is a function of information contributed by all participants in the key-agreement process so that no participant can predetermine the value of the resulting keying material independent of the contributions of the other participants. Key agreement is usually performed using automated protocols.

##### Key Transport

Key transport is a method whereby one party (the sender) generates a key and distributes it to one or more other parties (the receiver(s)). Key transport could be accomplished using manual methods (e.g., using a courier) or performed using automated protocols.

##### Key Wrapping

Key wrapping is a method used to provide confidentiality and integrity protection for keys (and possibly other information) using a symmetric-key block cipher algorithm and
symmetric key-wrapping keys that are known by both the sender and receiver. The wrapped keying material can then be stored or transmitted (i.e., distributed) securely.

Key wrapping differs from simple encryption in that the wrapping process includes both encryption and integrity protection. During the unwrapping process, a method for integrity verification is used to detect accidental or intentional modifications to the wrapped keying material.

### Random Bit Generation

Random bit generators (RBGs) (also called random number generators (RNGs)) generate sequences of random bits (e.g., 010011)and are required for the generation of keying material (e.g., keys and IVs).

The term "entropy" is used to describe the amount of randomness in a value, and the amount of entropy determines how hard it is to guess that value. RBGs rely on entropy sources to provide unpredictable bits, which are acquired from some physical source, such as thermal noise, ring oscillators, or hard-drive seek times.

There are two classes of random bit generators (RBGs):

- Non-Deterministic Random Bit Generators (NRBGs), or true RBG, are directly dependent on the availability of new bits produced by the entropy source for every output.
- Deterministic Random Bit Generators (DRBGs), or pseudo RBG, must be initially "seeded" with entropy produced by an entropy source or using an approved method that depends on an entropy source (e.g., using an NRBG).

## Cryptography Implementations

### Validated Cryptographic Modules

Whenever cryptography is used for the protection of sensitive information, for example encryption, an **approved cryptographic algorithm** (e.g. AES) must be selected and used following the best practices and avoididng common configuration issues. But that's not enough, according to NIST, only cryptographic modules containing validated implementations of these algorithms must be used.

The use of a **validated cryptographic module**, such as those validated by [FIPS 140](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.140-3.pdf), provides a minimum level of assurance that the product's stated security claim is valid. This FIPS 140 standard covers implementations of cryptographic modules including, but not limited to, hardware components or modules, software/firmware programs or modules or any combination thereof.

See "5.4.5 Use Validated Algorithms and Cryptographic Modules" in [NIST SP 800-175B Rev. 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175Br1.pdf) for more information and consult NIST's [Cryptographic Module Validation Program (CMVP) database](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search) to find validated cryptographic modules (for instance [BoringCrypto Android (aka. BoringSSL)](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3753) or [Apple corecrypto User Space Module for ARM](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3856)).

### Platform-Provided Cryptographic APIs vs Custom Implementations of Cryptography

Inventing proprietary cryptographic functions is time consuming, difficult, and likely to fail. For instance, among other things you'd need to follow appropriate standards such as ["FIPS PUB 140-2 - Security Requirements for Cryptographic Modules"](https://csrc.nist.gov/csrc/media/publications/fips/140/2/final/documents/fips1402.pdf). If you take a short look at the standard and some of the companion documents such as the ["Implementation Guidance for FIPS 140-2 and the Cryptographic Module Validation Program"](https://csrc.nist.gov/csrc/media/projects/cryptographic-module-validation-program/documents/fips140-2/fips1402ig.pdf) you can get a feeling of how complex this process is.

Instead of implementing cryptographic modules yourself, you should better rely on well-known standard compliant cryptographic modules such as those offered by the mobile operating systems. Those modules are usually available via platform-provided cryptographic APIs.

- Android uses [conscrypt](https://source.android.com/docs/core/architecture/modular-system/conscrypt) which relies on [BoringCrypto Android (aka. BoringSSL)](https://boringssl.googlesource.com/boringssl/) which is [FIPS-2 certified](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3753).
- iOS uses [CryptoKit](https://developer.apple.com/documentation/CryptoKit) which is based on [corecrypto](https://developer.apple.com/security/) which is [FIPS-2 certified](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3856).

These modules will take care of the complexity for you, for instance Apple states that you should avoid using lower-level interfaces and use CryptoKit instead since it frees your app from managing raw pointers, and automatically handles tasks that make your app more secure, like overwriting sensitive data during memory deallocation. So unless you are dealing with a very specific cryptography requirement where [CryptoKit is not enough](https://www.andyibanez.com/posts/cryptokit-not-enough/), you can always resort to other lower level APIs such as CommonCrypto or as a last resort to third-party libraries. For instance, CryptoKit offers AES-GCM but you might need to use AES-CBC for some reason. On that case, it would be understandable that the app rely on CommonCrypto.

When analyzing mobile apps, you must carefully inspect all the cryptographic methods used within the source code, especially those that are directly applied to sensitive data.

- Try to use the highest level of the pre-existing framework implementation that can support your use case.
- All cryptographic operations should use standard cryptographic APIs for Android and iOS.
- Any cryptographic operations that don't invoke standard routines from known providers should be closely inspected.
- Pay close attention to standard algorithms that have been modified.
- Remember that encoding isn't the same as encryption!
- Always investigate further when you find bit manipulation operators like XOR (exclusive OR).

## Common Cryptography Configuration Issues

### Insufficient Key Length

Even the most secure encryption algorithm becomes vulnerable to brute-force attacks when that algorithm uses an insufficient key size.

Ensure that the key length fulfills [accepted industry standards](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014 "ENISA Algorithms, key size and parameters report 2014").

### Key Reuse

Never reuse the key(pair) for another purpose: this might allow leaking information about the key: have a separate key pair for signing and a separate key(pair) for encryption.

### Weak Key Generation Functions

Cryptographic algorithms (such as symmetric encryption or some MACs) expect a secret input of a given size. For example, AES uses a key of exactly 16 bytes. A native implementation might use the user-supplied password directly as an input key. Using a user-supplied password as an input key has the following problems:

- If the password is smaller than the key, the full key space isn't used. The remaining space is padded (spaces are sometimes used for padding).
- A user-supplied password will realistically consist mostly of displayable and pronounceable characters. Therefore, only some of the possible 256 ASCII characters are used and entropy is decreased by approximately a factor of four.

Ensure that passwords aren't directly passed into an encryption function. Instead, the user-supplied password should be passed into a KDF to create a cryptographic key. Choose an appropriate iteration count when using password derivation functions. For example, [NIST recommends an iteration count of at least 10,000 for PBKDF2](https://pages.nist.gov/800-63-3/sp800-63b.html#sec5 "NIST Special Publication 800-63B") and [for critical keys where user-perceived performance is not critical at least 10,000,000](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf "NIST Special Publication 800-132"). For critical keys, it is recommended to consider implementation of algorithms recognized by [Password Hashing Competition (PHC)](https://password-hashing.net/ "PHC") like [Argon2](https://github.com/p-h-c/phc-winner-argon2 "Argon2").

### Weak Random Number Generators

It is fundamentally impossible to produce truly random numbers on any deterministic device. Pseudo-random number generators (RNG) compensate for this by producing a stream of pseudo-random numbers - a stream of numbers that appear as if they were randomly generated. The quality of the generated numbers varies with the type of algorithm used. Cryptographically secure RNGs generate random numbers that pass statistical randomness tests, and are resilient against prediction attacks (e.g. it is statistically infeasible to predict the next number produced).

Mobile SDKs offer standard implementations of RNG algorithms that produce numbers with sufficient artificial randomness. We'll introduce the available APIs in the Android and iOS specific sections.

### Inadequate AES Configuration

Advanced Encryption Standard (AES) is the widely accepted standard for symmetric encryption in mobile apps. It's an iterative block cipher that is based on a series of linked mathematical operations. AES performs a variable number of rounds on the input, each of which involve substitution and permutation of the bytes in the input block. Each round uses a 128-bit round key which is derived from the original AES key.

As of this writing, no efficient cryptanalytic attacks against AES have been discovered. However, implementation details and configurable parameters such as the block cipher mode leave some margin for error.

#### Weak Block Cipher Mode

Block-based encryption is performed upon discrete input blocks (for example, AES has 128-bit blocks). If the plaintext is larger than the block size, the plaintext is internally split up into blocks of the given input size and encryption is performed on each block. A block cipher mode of operation (or block mode) determines if the result of encrypting the previous block impacts subsequent blocks.

[ECB (Electronic Codebook)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_%28ECB%29 "Electronic Codebook (ECB)") divides the input into fixed-size blocks that are encrypted separately using the same key. If multiple divided blocks contain the same plaintext, they will be encrypted into identical ciphertext blocks which makes patterns in data easier to identify. In some situations, an attacker might also be able to replay the encrypted data.

<img src="Images/Chapters/0x07c/EncryptionMode.png" width="550px" />

Verify that Cipher Block Chaining (CBC) mode is used instead of ECB. In CBC mode, plaintext blocks are XORed with the previous ciphertext block. This ensures that each encrypted block is unique and randomized even if blocks contain the same information. Please note that it is best to combine CBC with an HMAC and/or ensure that no errors are given such as "Padding error", "MAC error", "decryption failed" in order to be more resistant to a padding oracle attack.

When storing encrypted data, we recommend using a block mode that also protects the integrity of the stored data, such as Galois/Counter Mode (GCM). The latter has the additional benefit that the algorithm is mandatory for each TLSv1.2 implementation, and thus is available on all modern platforms.

For more information on effective block modes, see the [NIST guidelines on block mode selection](https://csrc.nist.gov/groups/ST/toolkit/BCM/modes_development.html "NIST Modes Development, Proposed Modes").

#### Predictable Initialization Vector

CBC, OFB, CFB, PCBC, GCM mode require an initialization vector (IV) as an initial input to the cipher. The IV doesn't have to be kept secret, but it shouldn't be predictable: it should be random and unique/non-repeatable for each encrypted message. Make sure that IVs are generated using a cryptographically secure random number generator. For more information on IVs, see [Crypto Fail's initialization vectors article](http://www.cryptofails.com/post/70059609995/crypto-noobs-1-initialization-vectors "Crypto Noobs #1: Initialization Vectors").

Pay attention to cryptographic libraries used in the code: many open source libraries provide examples in their documentations that might follow bad practices (e.g. using a hardcoded IV). A popular mistake is copy-pasting example code without changing the IV value.

#### Initialization Vectors in stateful operation modes

Please note that the usage of IVs is different when using CTR and GCM mode in which the initialization vector is often a counter (in CTR combined with a nonce). So here using a predictable IV with its own stateful model is exactly what is needed. In CTR you have a new nonce plus counter as an input to every new block operation. For example: for a 5120 bit long plaintext: you have 20 blocks, so you need 20 input vectors consisting of a nonce and counter. Whereas in GCM you have a single IV per cryptographic operation, which should not be repeated with the same key. See section 8 of the [documentation from NIST on GCM](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode and GMAC") for more details and recommendations of the IV.

### Padding Oracle Attacks due to Weaker Padding or Block Operation Implementations

In the old days, [PKCS1.5](https://tools.ietf.org/html/rfc2313 "PCKS1.5 in RFC2313") padding (in code: `PKCS1Padding`) was used as a padding mechanism when doing asymmetric encryption. This mechanism is vulnerable to the padding oracle attack. Therefore, it is best to use OAEP (Optimal Asymmetric Encryption Padding) captured in [PKCS#1 v2.0](https://tools.ietf.org/html/rfc2437 "PKCS1 v2.0 in RFC 2437") (in code: `OAEPPadding`, `OAEPwithSHA-256andMGF1Padding`, `OAEPwithSHA-224andMGF1Padding`, `OAEPwithSHA-384andMGF1Padding`, `OAEPwithSHA-512andMGF1Padding`). Note that, even when using OAEP, you can still run into an issue known best as the Mangers attack as described [in the blog at Kudelskisecurity](https://research.kudelskisecurity.com/2018/04/05/breaking-rsa-oaep-with-mangers-attack/ "Kudelskisecurity").

Note: AES-CBC with PKCS #5 has shown to be vulnerable to padding oracle attacks as well, given that the implementation gives warnings, such as "Padding error", "MAC error", or "decryption failed". See [The Padding Oracle Attack](https://robertheaton.com/2013/07/29/padding-oracle-attack/ "The Padding Oracle Attack") and [The CBC Padding Oracle Problem](https://eklitzke.org/the-cbc-padding-oracle-problem "The CBC Padding Oracle Problem") for an example. Next, it is best to ensure that you add an HMAC after you encrypt the plaintext: after all a ciphertext with a failing MAC will not have to be decrypted and can be discarded.

### Insecure and/or Deprecated Cryptographic Algorithms

When assessing a mobile app, you should make sure that it does not use cryptographic algorithms and protocols that have significant known weaknesses or are otherwise insufficient for modern security requirements. Algorithms that were considered secure in the past may become insecure over time; therefore, it's important to periodically check current best practices and adjust configurations accordingly.

Verify that cryptographic algorithms are up to date and in-line with industry standards. Vulnerable algorithms include outdated block ciphers (such as DES and 3DES), stream ciphers (such as RC4), hash functions (such as MD5 and SHA1), and broken random number generators (such as Dual_EC_DRBG and SHA1PRNG). Note that even algorithms that are certified (for example, by NIST) can become insecure over time. A certification does not replace periodic verification of an algorithm's soundness. Algorithms with known weaknesses should be replaced with more secure alternatives. Additionally, algorithms used for encryption must be standardized and open to verification. Encrypting data using any unknown, or proprietary algorithms may expose the application to different cryptographic attacks which may result in recovery of the plaintext.

Inspect the app's source code to identify instances of cryptographic algorithms that are known to be weak, such as:

- [DES, 3DES](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014 "ENISA Algorithms, key size and parameters report 2014")
- RC2
- RC4
- [BLOWFISH](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014 "ENISA Algorithms, key size and parameters report 2014")
- MD4
- MD5
- SHA1

The names of cryptographic APIs depend on the particular mobile platform.

Please make sure that:

- Cryptographic algorithms are up to date and in-line with industry standards. This includes, but is not limited to outdated block ciphers (e.g. DES), stream ciphers (e.g. RC4), as well as hash functions (e.g. MD5) and broken random number generators like Dual_EC_DRBG (even if they are NIST certified). All of these should be marked as insecure and should not be used and removed from the application and server.
- Key lengths are in-line with industry standards and provide protection for sufficient amount of time. A comparison of different key lengths and protection they provide taking into account Moore's law is available [online](https://www.keylength.com/ "Keylength comparison").
- Cryptographic means are not mixed with each other: e.g. you do not sign with a public key, or try to reuse a key pair used for a signature to do encryption.
- Cryptographic parameters are well defined within reasonable range. This includes, but is not limited to: cryptographic salt, which should be at least the same length as hash function output, reasonable choice of password derivation function and iteration count (e.g. PBKDF2, scrypt or bcrypt), IVs being random and unique, fit-for-purpose block encryption modes (e.g. ECB should not be used, except specific cases), key management being done properly (e.g. 3DES should have three independent keys) and so on.

The following algorithms are recommended:

- Confidentiality algorithms: AES-GCM-256 or ChaCha20-Poly1305
- Integrity algorithms: SHA-256, SHA-384, SHA-512, BLAKE3, the SHA-3 family
- Digital signature algorithms: RSA (3072 bits and higher), ECDSA with NIST P-384
- Key establishment algorithms: RSA (3072 bits and higher), DH (3072 bits or higher), ECDH with NIST P-384

Additionally, you should always rely on secure hardware (if available) for storing encryption keys, performing cryptographic operations, etc.

For more information on algorithm choice and best practices, see the following resources:

- ["Commercial National Security Algorithm Suite and Quantum Computing FAQ"](https://cryptome.org/2016/01/CNSA-Suite-and-Quantum-Computing-FAQ.pdf "Commercial National Security Algorithm Suite and Quantum Computing FAQ")
- [NIST recommendations (2019)](https://www.keylength.com/en/4/ "NIST recommendations")
- [BSI recommendations (2019)](https://www.keylength.com/en/8/ "BSI recommendations")

## Key Management

In larger organizations, or when high-risk applications are created, it can often be a good practice to have a cryptographic policy, based on frameworks such as [NIST Recommendation for Key Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf "NIST 800-57 Rev5"). When basic errors are found in the application of cryptography, it can be a good starting point of setting up a lessons learned / cryptographic key management policy.

### The Problem with Hardcoded Keys

The security of symmetric encryption and keyed hashes (MACs) depends on the secrecy of the key. If the key is disclosed, the security gained by encryption is lost. To prevent this, never store secret keys in the same place as the encrypted data they helped create. A common mistake is encrypting locally stored data with a static, hardcoded encryption key and compiling that key into the app. This makes the key accessible to anyone who can use a disassembler.

For an encryption key, being hardcoded means that the key is:

- part of application resources
- value which can be derived from known values
- embedded in the source code

When analyzing mobiel apps, ensure that no keys or passwords are stored within the source code. This includes native code, JavaScript/Dart code, Java/Kotlin code on Android and Objective-C/Swift in iOS. Note that hardcoded keys are problematic even if the source code is obfuscated since obfuscation is easily bypassed by dynamic instrumentation.

### Protecting Keys in Storage and in Memory

When memory dumping is part of your threat model, then keys can be accessed the moment they are actively used. Memory dumping either requires root-access (e.g. a rooted device or jailbroken device) or it requires a patched application with Frida (so you can use tools like Fridump).
Therefore it is best to consider the following, if keys are still needed at the device:

- **Keys in a Remote Server**: you can use remote Key vaults such as Amazon KMS or Azure Key Vault. For some use cases, developing an orchestration layer between the app and the remote resource might be a suitable option. For instance, a serverless function running on a Function as a Service (FaaS) system (e.g. AWS Lambda or Google Cloud Functions) which forwards requests to retrieve an API key or secret. There are other alternatives such as Amazon Cognito, Google Identity Platform or Azure Active Directory.
- **Keys inside Secure Hardware-backed Storage**: make sure that all cryptographic actions and the key itself remain in the Trusted Execution Environment (e.g. use [Android Keystore](https://developer.android.com/training/articles/keystore.html "Android keystore system")) or [Secure Enclave](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave "Storing Keys in the Secure Enclave") (e.g. use the Keychain). Refer to the [Android Data Storage](0x05d-Testing-Data-Storage.md#storing-keys-using-hardware-backed-android-keystore) and [iOS Data Storage](0x06d-Testing-Data-Storage.md#the-keychain) chapters for more information.
- **Keys protected by Envelope Encryption**: If keys are stored outside of the TEE / SE, consider using multi-layered encryption: an _envelope encryption_ approach (see [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#encrypting-stored-keys "OWASP Cryptographic Storage Cheat Sheet: Encrypting Stored Keys"), [Google Cloud Key management guide](https://cloud.google.com/kms/docs/envelope-encryption?hl=en "Google Cloud Key management guide: Envelope encryption"), [AWS Well-Architected Framework guide](https://docs.aws.amazon.com/wellarchitected/latest/financial-services-industry-lens/use-envelope-encryption-with-customer-master-keys.html "AWS Well-Architected Framework")), or [a HPKE approach](https://tools.ietf.org/html/draft-irtf-cfrg-hpke-08 "Hybrid Public Key Encryption") to encrypt data encryption keys with key encryption keys.
- **Keys in Memory**: make sure that keys live in memory for the shortest time possible and consider zeroing out and nullifying keys after successful cryptographic operations, and in case of error. For general cryptocoding guidelines, refer to [Clean memory of secret data](https://github.com/veorq/cryptocoding#clean-memory-of-secret-data/ "The Cryptocoding Guidelines by @veorq: Clean memory of secret data"). For more detailed information refer to sections [Testing Memory for Sensitive Data](0x05d-Testing-Data-Storage.md#testing-memory-for-sensitive-data-mstg-storage-10) and [Testing Memory for Sensitive Data](0x06d-Testing-Data-Storage.md#testing-memory-for-sensitive-data-mstg-storage-10) for Android and iOS respectively.

Note: given the ease of memory dumping, never share the same key among accounts and/or devices, other than public keys used for signature verification or encryption.

### Protecting Keys in Transport

When keys need to be transported from one device to another, or from the app to a backend, make sure that proper key protection is in place, by means of a transport keypair or another mechanism. Often, keys are shared with obfuscation methods which can be easily reversed. Instead, make sure asymmetric cryptography or wrapping keys are used. For example, a symmetric key can be encrypted with the public key from an asymmetric key pair.

## Cryptography Regulations

When you upload the app to the App Store or Google Play, your application is typically stored on a US server. If your app contains cryptography and is distributed to any other country, it is considered a cryptography export. It means that you need to follow US export regulations for cryptography. Also, some countries have import regulations for cryptography.

Learn more:

- [Complying with Encryption Export Regulations (Apple)](https://developer.apple.com/documentation/security/complying_with_encryption_export_regulations "Complying with Encryption Export Regulations")
- [Export compliance overview (Apple)](https://help.apple.com/app-store-connect/#/dev88f5c7bf9 "Export compliance overview")
- [Export compliance (Google)](https://support.google.com/googleplay/android-developer/answer/113770?hl=en "Export compliance")
- [Encryption and Export Administration Regulations (USA)](https://www.bis.doc.gov/index.php/policy-guidance/encryption "Encryption and Export Administration Regulations")
- [Encryption Control (France)](https://www.ssi.gouv.fr/en/regulation/cryptology/ "Encryption Control")
- [World map of encryption laws and policies](https://www.gp-digital.org/WORLD-MAP-OF-ENCRYPTION/)

## References

### OWASP MASVS

- MSTG-ARCH-8: "There is an explicit policy for how cryptographic keys (if any) are managed, and the lifecycle of cryptographic keys is enforced. Ideally, follow a key management standard such as NIST SP 800-57."
- MSTG-CRYPTO-1: "The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption."
- MSTG-CRYPTO-2: "The app uses proven implementations of cryptographic primitives."
- MSTG-CRYPTO-3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices."
- MSTG-CRYPTO-4: "The app does not use cryptographic protocols or algorithms that are widely considered deprecated for security purposes."

### Cryptography

- [Argon2](https://github.com/p-h-c/phc-winner-argon2 "Argon2")
- [AWS Well-Architected Framework guide](https://docs.aws.amazon.com/wellarchitected/latest/financial-services-industry-lens/use-envelope-encryption-with-customer-master-keys.html "AWS Well-Architected Framework")
- [Breaking RSA with Mangers Attack](https://research.kudelskisecurity.com/2018/04/05/breaking-rsa-oaep-with-mangers-attack/ "Mangers attack")
- [Google Cloud Key management guide](https://cloud.google.com/kms/docs/envelope-encryption?hl=en "Google Cloud Key management guide: Envelope encryption")
- [Hybrid Public Key Encryption](https://tools.ietf.org/html/draft-irtf-cfrg-hpke-08 "Hybrid Public Key Encryption")
- [NIST 800-38d](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf "NIST 800-38d")
- [NIST 800-57Rev5](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final "NIST 800-57Rev5")
- [NIST 800-63b](https://pages.nist.gov/800-63-3/sp800-63b.html "NIST 800-63b")
- [NIST 800-132](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf "NIST 800-132")
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#encrypting-stored-keys "OWASP Cryptographic Storage Cheat Sheet: Encrypting Stored Keys")
- [Password Hashing Competition(PHC)](https://password-hashing.net "PHC")
- [PKCS #1: RSA Encryption Version 1.5](https://tools.ietf.org/html/rfc2313 "PKCS #1: RSA Encryption Version 1.5")
- [PKCS #1: RSA Cryptography Specifications Version 2.0](https://tools.ietf.org/html/rfc2437 "PKCS #1: RSA Cryptography Specifications Version 2.0")
- [PKCS #7: Cryptographic Message Syntax Version 1.5](https://tools.ietf.org/html/rfc2315 "PKCS #7")
- [The Padding Oracle Attack](https://robertheaton.com/2013/07/29/padding-oracle-attack "The Padding Oracle Attack")
- [The CBC Padding Oracle Problem](https://eklitzke.org/the-cbc-padding-oracle-problem "The CBC Padding Oracle Problem")
- [Cryptocoding Guidelines by veorq](https://github.com/veorq/cryptocoding "The Cryptocoding Guidelines by veorq")
- [Mitigating Cryptographic Mistakes by Design](https://svs.informatik.uni-hamburg.de/publications/2019/2019-09-05-crypto-api-design-muc2019.pdf "Mitigating Cryptographic Mistakes by Design")
- [CRYLOGGER: Detecting Crypto Misuses Dynamically](https://arxiv.org/pdf/2007.01061.pdf "CRYLOGGER: Detecting Crypto Misuses Dynamically")