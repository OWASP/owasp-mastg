## Cryptography for Mobile Apps

This chapter provides an outline of cryptographic concepts and best practices relevant to mobile apps. Platform-specific cryptographic APIs for data storage are covered in greater detail "Testing Data Storage" chapters. Encryption of network traffic - in particular Transport Layer Security (TLS) - is covered in the “Testing Network Communication” chapter.

### Key Concepts

The primary goal of cryptography is to provide confidentiality, data integrity, and authenticity, even in the face of an attack. Confidentiality is achieved through use of encryption, with the aim of ensuring secrecy of the contents. Data integrity deals with maintaining and ensuring consistency of data and detection of tampering/modification. Authenticity ensures that the data comes from a trusted source. 

- Encryption ensures data confidentiality by using special algorithms to convert plaintext data into cipher text, which does not reveal any information about the original content. Plaintext data can be restored from the cipher text through decryption. Two main forms of encryption are symmetric (or secret key) and asymmetric (or public key). In general, encryption operations do not protect integrity, but some symmetric encryption modes also feature that protection.
  - Symmetric-key encryption algorithms use the same key for both encryption and decryption. It is fast and suitable for bulk data processing. Since everybody who has access to the key is able to decrypt the encrypted content, they require careful key management.
  - Public-key (or asymmetric) encryption algorithms operate with two separate keys: the public key and the private key. The public key can be distributed freely, while the private key should not be shared with anyone. A message encrypted with the public key can only be decrypted with the private key. Since asymmetric encryption is several times slower than symmetric operations, it is typically only used to encrypt small amounts of data, such as symmetric keys for bulk encryption.
- Hash functions deterministically map arbitrary pieces of data into fixed-length values. It is typically easy to compute the hash, but difficult (or impossible) to determine the original input based on the hash. Cryptographic hash functions additionally guarantee that even small changes to the input data result in large changes to the resulting hash values. Cryptographic hash functions are used for integrity verification, but do not provide authenticity guarantees.
- Message Authentication Codes, or MACs, combine other cryptographic mechanisms, such as symmetric encryption or hashes, with secret keys to provide both integrity and authenticity protection. However, in order to verify a MAC, multiple entities have to share the same secret key, and any of those entities will be able to generate a valid MAC. The most commonly used type of MAC, called HMAC, relies on hashing as the underlying cryptographic primitive. As a rule, the full name of an HMAC algorithm also includes the name of the underlying hash, e.g. - HMAC-SHA256.
- Signatures combine asymmetric cryptography (i.e. - using a public/private key pair) with hashing to provide integrity and authenticity by encrypting the hash of the message with the private key. However, unlike MACs, signatures also provide non-repudiation property, as the private key should remain unique to the data signer.
- Key Derivation Functions, or KDFs, are often confused with password hashing functions. KDFs do have many useful properties for password hashing, but were created with different purposes in mind. In context of mobile applications, it is the password hashing functions that are typically meant for protecting stored passwords.

### Testing for Insecure and/or Deprecated Cryptographic Algorithms

#### Overview

Many cryptographic algorithms and protocols should not be used because they have been shown to have significant weaknesses or are otherwise insufficient for modern security requirements. Previously thought secure algorithms may become insecure over time. It is therefore important to periodically check current best practices and adjust configurations accordingly.

#### Static Analysis

Verify that that cryptographic algorithms are up to date and in-line with industry standards. This includes, but is not limited to outdated block ciphers (e.g. DES), stream ciphers (e.g. RC4), as well as hash functions (e.g. MD5) and broken random number generators like Dual_EC_DRBG. Please note, that an algorithm that was certified, e.g., by NIST, can also become insecure over time. A certification does not replace periodic verification of an algorithm's soundness. All of these should be marked as insecure and should not be used and removed from the application code base.

Inspect the source code to identify the instances of cryptographic algorithms throughout the application, and look for known weak ones, such as:

- [DES, 3DES](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014 "ENISA Algorithms, key size and parameters report 2014")
- RC2
- RC4
- [BLOWFISH](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014 "ENISA Algorithms, key size and parameters report 2014")
- MD4
- MD5
- SHA1 and others.

On Android (via Java Cryptography APIs), selecting an algorithm is done by requesting an instance of the `Cipher` (or other primitive) by passing a string containing the algorithm name. For example, `Cipher cipher = Cipher.getInstance("DES");`. On iOS, algorithms are typically selected using predefined constants defined in CommonCryptor.h, e.g., `kCCAlgorithmDES`. Thus, searching the source code for the presence of these algorithm names would indicate that they are used. Note that since the constants on iOS are numeric, an additional check needs to be performed to check whether the algorithm values sent to CCCrypt function map to one of the deprecated/insecure algorithms.

The following algorithms are recommended:

- Confidentiality: AES-GCM-256 or ChaCha20-Poly1305
- Integrity: SHA-256, SHA-384, SHA-512, Blake2
- Digital signature: RSA (3072 bits and higher), ECDSA with NIST P-384
- Key establishment: RSA (3072 bits and higher), DH (3072 bits or higher), ECDH with NIST P-384
- Rely on secure hardware, if available, for storing encryption keys, performing cryptographic operations, etc.

See also the following best practice documents for recommendations:
- ["Commercial National Security Algorithm Suite and Quantum Computing FAQ"](https://cryptome.org/2016/01/CNSA-Suite-and-Quantum-Computing-FAQ.pdf "Commercial National Security Algorithm Suite and Quantum Computing FAQ")
- [NIST recommendations (2016)](https://www.keylength.com/en/4/ "NIST recommendations")
- [BSI recommendations (2017)](https://www.keylength.com/en/8/ "BSI recommendations")

#### References

##### OWASP Mobile Top 10

- M6 - Broken Cryptography

##### OWASP MASVS

- V3.3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices."
- V3.4: "The app does not use cryptographic protocols or algorithms that are widely considered depreciated for security purposes."

##### CWE

- CWE-326: Inadequate Encryption Strength
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm

### Testing for Misuse and Misconfiguration of Cryptography

#### Overview

Choosing strong cryptographic algorithm alone is not enough. Often security of otherwise sound algorithms can be affected through their configuration. Most prominent for cryptographic algorithms is the selection of their used key length.

#### Static Analysis

Check the source code for any of the following misconfigurations.

##### Insufficient Key Length

Even the most secure encryption algorithm becomes vulnerable to brute-force attacks when an insufficient key size is used.

Ensure that used key length fulfill [accepted industry standards](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014 "ENISA Algorithms, key size and parameters report 2014"). Also verify the used [security "Crypto" provider on the Android platform](https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html "Security Crypto provider on the Android platform deprecated in Android N").

##### Weak AES Configuration

###### Block Mode

Block-based encryption is performed upon discrete input blocks, e.g., 128 bit blocks when using AES. If the plain-text is larger than the block-size, it is internally split up into blocks of the given input size and encryption is performed upon each block. The so called block mode defines, if the result of one encrypted block has any impact upon subsequently encrypted blocks.

The [ECB (Electronic Codebook)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29 "Electronic Codebook (ECB)") encryption mode should not be used, as it is basically divides the input into blocks of fixed size and each block is encrypted separately. For example, if an image is encrypted utilizing the ECB block mode, then the input image is split up into multiple smaller blocks. Each block might represent a small area of the original image. Each of which is encrypted using the same secret input key. If input blocks are similar, e.g., each input block is just a white background, the resulting encrypted output block will also be the same. While each block of the resulting encrypted image is encrypted, the overall structure of the image will still be recognizable within the resulting encrypted image.

![Electronic Codebook (ECB mode encryption)](Images/Chapters/0x07c/ECB.png)

![Difference of encryption modes](Images/Chapters/0x07c/EncryptionMode.png)

Use an established block mode that provides a feedback mechanism for subsequent blocks, e.g. Counter Mode (CTR). For storing encrypted data it is often advisable to use a block mode that additionally protects the integrity of the stored data, e.g. Galois/Counter Mode (GCM). The latter has the additional benefit that the algorithm is mandatory for each TLSv1.2 implementation -- thus being available on all modern platforms.

Also consult the [NIST guidelines on block mode selection](http://csrc.nist.gov/groups/ST/toolkit/BCM/modes_development.html "NIST Modes Development, Proposed Modes").

##### Initialization Vector

- [Initialization vectors (IVs)](http://www.cryptofails.com/post/70059609995/crypto-noobs-1-initialization-vectors

###### Symmetric Encryption with Hard-coded Cryptographic Keys

The security of symmetric encryption and keyed hashes (MACs) is highly dependent upon the secrecy of the used secret key. If the secret key is disclosed, the security gained by encryption/MACing is rendered naught. This mandates that the secret key is protected and should not be stored together with the encrypted data.

A common mistake developers make is to encrypt locally stored data with a static encryption key and compiling that key into the app. In that case, the key is accessible by anyone who can use a disassembler.

- Ensure that no keys/passwords are hard-and stored within the source code. Note that hard-coded keys are a problem even if the source code is obfuscated: Obfuscation is easily bypassed by dynamic instrumentation and in principle does not differ from hard coded keys.
- If the app is using two-way SSL (i.e. there is both server and client certificate validated) check if:
    - the password to the client certificate is not stored locally, or is locked in the device Keychain
    - the client certificate is not shared among all installations (e.g. hard coded in the app)
- If the app relies on an additional encrypted container stored in app data, ensure how the encryption key is used:
    - if key wrapping scheme is used, ensure that the master secret is initialized for each user, or container is re-encrypted with new key;
    - check how password change is handled and specifically, if you can use master secret or previous password to decrypt the container.

Whenever symmetric cryptography is used in mobile apps, the associated secret keys must be stored in secure device storage. For mote information on the platform-specific APIs, refer to the "Testing Data Storage" chapters.





##### Weak Key Generation Functions

Cryptographic algorithms, such as symmetric encryption or MACs, expect a secret input of a given size, e.g. 128 or 256 bit. A native implementation might use the user-supplied password directly as an input key. There are a couple of problems with this approach:

- If the password is smaller than the key, then not the full key-space is used (the rest is padded, sometimes even with spaces)
- A user-supplied password will realistically consist mostly of displayable and pronounceable characters. So instead of the full entropy, i.e. 2<sup>8</sup> when using ASCII, only a small subset is used (approx. 2<sup>6</sup>).
- If two users select the same password an attacker can match the encrypted files. This opens up the possibility of rainbow table attacks.

Verify that no password is directly passed into an encryption function. Instead, the user-supplied password should be passed into a salted hash function or KDF to create the cryptographic key.

- Reasonable choice of iteration counts when using password derivation functions

##### Custom Implementations of Cryptography

Inventing proprietary cryptographic functions is time consuming, difficult and very likely to fail. Instead, well-known algorithms that are widely regarded as secure should be used. Mobile operating systems offer standard cryptographic APIs that implement those algorithms.

Carefully inspect all the cryptographic methods used within the source code, especially those which are directly applied to sensitive data. All cryptographic operations (see the list in the introduction section) should come from the standard providers (for standard APIs for Android and iOS, see cryptography chapters for the respective platforms). Any cryptographic invocations which do not invoke standard routines from known providers should be candidates for closer inspection. Pay close attention to seemingly standard but modified algorithms. Remember that encoding is not encryption! Any appearance of bit manipulation operators like XOR (exclusive OR) might be a good sign to start digging deeper.

#### References

##### OWASP Mobile Top 10

- M6 - Broken Cryptography

##### OWASP MASVS

- V3.1: "The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption."
- V3.2: "The app uses proven implementations of cryptographic primitives."
- V3.3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices."
- V3.4: "The app does not use cryptographic protocols or algorithms that are widely considered depreciated for security purposes."

##### CWE

- CWE-326: Inadequate Encryption Strength
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- CWE-329: Not Using a Random IV with CBC Mode
