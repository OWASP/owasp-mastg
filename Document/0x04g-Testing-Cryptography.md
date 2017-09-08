> NOTE: this is a very rough first pass to work on clearing up the meaning of the content and to work on organization and getting other questions answered. Grammar, typos, etc are not fully edited and polished yet, so feel free to ignore as this will be dealt with at a later editing stage.

> I'm trying out using **bold** for the first use of key concepts to improve scannability and help the reader

## Testing Cryptography in Mobile Apps

This chapter provides an outline of cryptographic concepts and best practices relevant to mobile apps. These best practices are valid on every mobile operating system. Platform-specific cryptographic APIs for data storage are covered in greater detail in the [**Testing Data Storage on Android**](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md) and [**Testing Data Storage on iOS**](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06d-Testing-Data-Storage.md) chapters. Encryption of network traffic, especially Transport Layer Security (TLS), is covered in the [**Testing Network Communication**](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md) chapter.

### Key Concepts

The goal of cryptography is to provide constant confidentiality, data integrity, and authenticity, even in the face of an attack. Confidentiality involves ensuring data privacy through the use of encryption. Data integrity deals with data consistency and detection of tampering and modification of data. Authenticity ensures that the data comes from a trusted source. 

Encryption algorithms converts plaintext data into cipher text that conceals the original content. Plaintext data can be restored from the cipher text through decryption. Encryption can be **symmetric** (secret-key encryption) or **asymmetric** (public-key encryption). In general, encryption operations do not protect integrity, but some symmetric encryption modes also feature that protection. 

**Symmetric-key encryption algorithms** use the same key for both encryption and decryption. This type of encryption is fast and suitable for bulk data processing. Since everybody who has access to the key is able to decrypt the encrypted content, this method requires careful key management. **Public-key encryption algorithms** operate with two separate keys: the public key and the private key. The public key can be distributed freely while the private key shouldn't be shared with anyone. A message encrypted with the public key can only be decrypted with the private key. Since asymmetric encryption is several times slower than symmetric operations, it's typically only used to encrypt small amounts of data, such as symmetric keys for bulk encryption.

**Hashing** isn't a form of encryption, but it does use cryptography. Hash functions deterministically map arbitrary pieces of data into fixed-length values. It's often easy to compute the hash, but difficult (or impossible) to use the hash to determine the original input. Additionally, cryptographic hash functions cause small changes in the input data to create large changes to the resulting hash values. Hash functions are used for integrity verification, but don't provide an authenticity guarantee.

> "result in large changes to the resulting hash values" - Do we need to say why that's good? Do we need to say hashing is most often used for passwords?
> From some googling, it seems that "authenticity guarantee" may be an industry term, just not one that is frequently used enough for me to get a good sense of its use. I think making it plural does work technically I guess, but it still is pretty awkward to read. Is there some way we can get around this? I changed it to the singular form for now. Below, the term "authenticity protection is used". Is that referring to the same concept as "authenticity guarantees"? Let's make references to this concept consistent. Edit: So are authenticity guarantee and authenticity protection the same thing? are both of these the same as authenticity verification?

**Message Authentication Codes** (MACs) combine other cryptographic mechanisms (such as symmetric encryption or hashes) with secret keys to provide both integrity and authenticity protection. However, in order to verify a MAC, multiple entities have to share the same secret key and any of those entities can generate a valid MAC. HMACs, the most commonly used type of MAC, rely on hashing as the underlying cryptographic primitive. The full name of an HMAC algorithm usually includes the underlying hash function's type (for example, HMAC-SHA256 uses the SHA-256 hash function).

**Signatures** combine asymmetric cryptography (that is, using a public/private key pair) with hashing to provide integrity and authenticity by encrypting the hash of the message with the private key. However, unlike MACs, signatures also provide non-repudiation property as the private key should remain unique to the data signer.

**Key Derivation Functions** (KDFs) derive secret keys from a secret value (such as a password) and are used to turn keys into other formats or to increase their length. KDFs are similar to hashing functions but have other uses as well (for example, they are used as components of multiparty key-agreement protocols). While both hashing functions and KDFs must be difficult to reverse, KDFs have the added requirement that the keys they produce must have a level of randomness. 

### Testing for Insecure and/or Deprecated Cryptographic Algorithms

We should avoid using the many cryptographic algorithms and protocols that have significant, demonstrative weaknesses or are otherwise insufficient for modern security requirements. Algorithms that were considered secure in the past may become insecure over time; therefore, it's important to periodically check current best practices and adjust configurations accordingly.

#### Static Analysis

We can use static analysis to verify that cryptographic algorithms are up to date and inline with industry standards. Algorithms to verify can include outdated block ciphers (such as DES), stream ciphers (such as RC4), hash functions (such as MD5), and broken random number generators (such as Dual_EC_DRBG). Note that even algorithms that are certified (for example, by NIST) can become insecure over time. A certification does not replace periodic verification of an algorithm's soundness. Algorithms with known weaknesses should be replaced with more secure alternatives.

First, inspect your app's source code to identify instances of cryptographic algorithms that are known to be weak, such as:

- [DES, 3DES](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014 "ENISA Algorithms, key size and parameters report 2014")
- RC2
- RC4
- [BLOWFISH](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014 "ENISA Algorithms, key size and parameters report 2014")
- MD4
- MD5
- SHA1

The method for inspecting and selecting insecure algorithms in your source code depends on your mobile platform. To select an algorithm on Android, we use `Cipher.getInstance("algorithm-name")` (part of the Java Cryptography API) in the app's source code to request an instance of the `Cipher` (or other primitive) that includes that algorithm. The argument to the `Cipher` class determines which algorithm is used (for example, `Cipher cipher = Cipher.getInstance("DES");`). To select an algorithm on iOS, we use predefined constants defined in `CommonCryptor.h` (for example, `kCCAlgorithmDES`). We can search source code for these constants to detect if they are used. Note that since the constants on iOS are numeric, make sure to check whether the algorithm constant values sent to the `CCCrypt` function represent an algorithm we know is insecure or deprecated. Once you have selected an insecure algorithm, you can work to redesign your solution to use a recommended algorithm instead.

> I'm still trying to understand all this. The wording is just confusing to me and it's hard to do a google search on this. What does selecting an algorithm mean? Are we finding algorithms or selecting algorithms? I'm just worried about a lot of the mixed wording here because I don't understand it. It could be ok, please check all of my wording.  

The following algorithms are recommended:

- Confidentiality algorithms: AES-GCM-256 or ChaCha20-Poly1305
- Integrity algorithms: SHA-256, SHA-384, SHA-512, Blake2
- Digital signature algorithms: RSA (3072 bits and higher), ECDSA with NIST P-384
- Key establishment algorithms: RSA (3072 bits and higher), DH (3072 bits or higher), ECDH with NIST P-384

Additionally, you should always rely on secure hardware (if available) for storing encryption keys, performing cryptographic operations, etc.

For more information on algorithm choice and best practices, see the following resources:
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

Choosing a strong cryptographic algorithm alone is not enough. Cryptography is very easy to implement incorrectly, even when you are using secure algorithms. Improper configuration in particular can negatively affect the security of an otherwise sound algorithm. 

> There was a recommendation in the feedback comments to write more about how crypto can be done wrong even with a great algorithm...but maybe this is covered in the esting for Misuse and Misconfiguration of Cryptography chapter? Where is this chapter, should I link to it?
> So, the links above also involve key length. Should this list of resources be moved to the bottom of this chapter? it did feel really weird having references and more resouces in the middle of a chapter. Also, hmm we have a section above on static analysis as well as below....can this all be reorganized and combined? well, the section above was about identifying weak algorithms...and now we are looking at how the good algorithms are configured. is this a sort of step 2 then? first weed out the bad, and now inspect the good for issues?

#### Static Analysis

Check the source code for any of the following misconfigurations.

##### Insufficient Key Length

Even the most secure encryption algorithm becomes vulnerable to brute-force attacks when that algorithm uses an insufficient key size.

Ensure that the key length fulfills [accepted industry standards](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014 "ENISA Algorithms, key size and parameters report 2014"). Also verify that the [security "Crypto" provider on the Android platform](https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html "Security Crypto provider on the Android platform deprecated in Android N").

> "Also verify the used security Crypto provider on the Android platform" <- verify for what? make sure it's not depreciated?

##### Weak AES Configuration

Advanced Encryption Standard (AES) is the widely accepted standard for symmetric encryption in mobile apps. It's an iterative block cipher that is based on a series of linked mathematical operations. AES performs a variable number of rounds on the input, each of which involve substitution and permutation of the bytes in the input block. Each round uses a 128-bit round key which is derived from the original AES key.

As of this writing, no efficient cryptanalytic attacks against AES have been discovered. However, implementation details and configurable parameters such as mode leave some margin for

###### Weak Block Cipher Mode

Block-based encryption is performed upon discrete input blocks (for example, AES has 128 bit blocks). If the plaintext is larger than the block size, the plaintext is internally split up into blocks of the given input size and encryption is performed on each block. A block cipher mode of operation (or block mode) determines if the result of an encrypted block impacts subsequent encrypted blocks.

> "The result of one encrypted block" <- Should this just be "if the encryption of one block has any impact..." I am wondering if there is some repetition here. "Encrypted block" already describes a thing that is the result of encryption that has been done to a block.

You shouldn't use [ECB (Electronic Codebook)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29 "Electronic Codebook (ECB)") encryption as this mode divides the input into fixed-size blocks that are encrypted separately using the same key. If multiple divided blocks contain the same plaintext, they will be encrypted into identical ciphertext blocks which makes patterns in data easier to identify. The overall structure of the input will still be recognizable within the resulting encrypted blocks. For example, the image below demonstrates how blocks of the same color create encrypted output that can be used to identify the image.

![Electronic Codebook (ECB mode encryption)](Images/Chapters/0x07c/ECB.png)

> not sure this image is necessary - nothing else has an in illustration like this

![Difference of encryption modes](Images/Chapters/0x07c/EncryptionMode.png)

Verify that Cipher Block Chaining (CBC) mode is used instead of ECB. In CBC mode, plaintext blocks are XORed with the previous ciphertext block. This ensures that each encrypted block is unique and randomized even if blocks contain the same information.

> So this says verify that CBC is used, but below it says GCM. I'm thinking this means CBC is recommended generally, but it says to go with GCM if you are storing the data since there is some added protection here. But yea is there is a reason not to just only recommend GCM for everything?

When storing encrypted data, we recommend using a block mode that also protects the integrity of the stored data, such as Galois/Counter Mode (GCM). The latter has the additional benefit that the algorithm is mandatory for each TLSv1.2 implementation, and thus is available on all modern platforms.

For more information on effective block modes, see the [NIST guidelines on block mode selection](http://csrc.nist.gov/groups/ST/toolkit/BCM/modes_development.html "NIST Modes Development, Proposed Modes").

###### Predictable Initialization Vector

CBC mode requires the first plaintext block to be combined with an initialization vector (IV). The IV doesn't have to be kept secret, but it shouldn't be predictable. Make sure that IVs are generated using a cryptographically-secure random number generator. For more information on IVs, see [Crypto Fail's initialization vectors article](http://www.cryptofails.com/post/70059609995/crypto-noobs-1-initialization-vectors).

###### Symmetric Encryption with Hard-Coded Cryptographic Keys

The security of symmetric encryption and keyed hashes (MACs) depends on the secrecy of the key. If the key is disclosed, the security gained by encryption is lost. To prevent this, never store secret keys in the same place as the encrypted data they helped create. Developers often make the mistake of encrypting locally stored data with a static, hard-coded encryption key and compiling that key into the app. This makes the key accessible to anyone who can use a disassembler.

First, ensure that no keys or passwords are stored within the source code. Note that hard-coded keys are problematic even if the source code is obfuscated since obfuscation is easily bypassed by dynamic instrumentation.

If the app is using two-way SSL (both server and client certificates are validated), make sure that:
    1. The password to the client certificate isn't stored locally or is locked in the device Keychain.
    2. The client certificate isn't shared among all installations.

> do you mean keyring instead of Keychain?

If the app relies on an additional encrypted containers stored in app data, check how the encryption key is used. If a key-wrapping scheme is used, ensure that the master secret is initialized for each user or the container is re-encrypted with new key. If you can use the master secret or previous password to decrypt the container, check how password changes are handled.

Secret keys must be stored in secure device storage whenever symmetric cryptography is used in mobile apps. For more information on the platform-specific APIs, see the [**Testing Data Storage on Android**](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md) and [**Testing Data Storage on iOS**](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06d-Testing-Data-Storage.md) chapters.

##### Weak Key Generation Functions

Cryptographic algorithms (such as symmetric encryption or some MACs) expect a secret input of a given size. For example, AES uses a key of exactly 16 bytes. A native implementation might use the user-supplied password directly as an input key. Using a user-supplied password as an input key has the following problems:

- If the password is smaller than the key, the full key space isn't used. The remaining space is padded (spaces are sometimes used for padding).
- A user-supplied password will realistically consist mostly of displayable and pronounceable characters. Therefore, only some of the possible 256 ASCII characters are used and entropy is decreased by approximately a factor of four.

> How can the password be smaller then the key when the password is being used as the key? Maybe I'm just not understanding, or there is some inconsistency with the lead-in paragraph and the first bullet?

Ensure that passwords aren't directly passed into an encryption function. Instead, the user-supplied password should be passed into a KDF to create a cryptographic key. Choose an appropriate iteration count when using password derivation functions. For example, [NIST recommends and iteration count of at least 10,000 for PBKDF2](https://pages.nist.gov/800-63-3/sp800-63b.html#sec5 "NIST Special Publication 800-63B").

##### Custom Implementations of Cryptography

Inventing proprietary cryptographic functions is time consuming, difficult, and likely to fail. Instead, we can use well-known algorithms that are widely regarded as secure. Mobile operating systems offer standard cryptographic APIs that implement those algorithms.

Carefully inspect all the cryptographic methods used within the source code, especially those that are directly applied to sensitive data. All cryptographic operations (listed in the introduction section) should come from known providers (for standard APIs for Android and iOS, see the cryptography chapters for those platforms). Any cryptographic operations that don't invoke standard routines from known providers should be closely inspected. Pay close attention to standard algorithms that have been modified. Remember that encoding isn't the same as encryption! Always investigate further when you find bit manipulation operators like XOR (exclusive OR).

> What introduction section? I'd like to be more specific. Also may need to clarify the platform-specific chapters mentioned in this paragraph - maybe use the names? Less sure about that one. Should this mean the "Testing Cryptography" chapters?

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
