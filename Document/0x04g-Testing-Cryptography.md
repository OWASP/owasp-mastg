> I'm trying out using **bold** for the first use of key concepts to improve scannability and help the reader

## Testing Cryptography in Mobile Apps

This chapter provides an outline of cryptographic concepts and best practices relevant to mobile apps. These best practices are valid on every mobile operating system. Platform-specific cryptographic APIs for data storage are covered in greater detail in the [**Testing Data Storage on Android**](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md) and [**Testing Data Storage on iOS**](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06d-Testing-Data-Storage.md) chapters. Encryption of network traffic, especially Transport Layer Security (TLS), is covered in the [**Testing Network Communication**](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md) chapter.

### Key Concepts

The goal of cryptography is to provide constant confidentiality, data integrity, and authenticity, even in the face of an attack. Confidentiality involves ensuring data privacy through the use of encryption. Data integrity deals with data consistency and detection of tampering and modification of data. Authenticity ensures that the data comes from a trusted source. 

Encryption uses special algorithms to convert plaintext data into cipher text that doesn't reveal any information about the original content. Plaintext data can be restored from the cipher text through decryption. Encryption can be **symmetric** (secret-key encryption) or **asymmetric** (public-key encryption). In general, encryption operations do not protect integrity, but some symmetric encryption modes also feature that protection. 

**Symmetric-key encryption algorithms** use the same key for both encryption and decryption. This type of encryption is fast and suitable for bulk data processing. Since everybody who has access to the key is able to decrypt the encrypted content, they require careful key management. **Public-key encryption algorithms** operate with two separate keys: the public key and the private key. The public key can be distributed freely while the private key shouldn't be shared with anyone. A message encrypted with the public key can only be decrypted with the private key. Since asymmetric encryption is several times slower than symmetric operations, it's typically only used to encrypt small amounts of data, such as symmetric keys for bulk encryption.

**Hashing** isn't a form of encryption, but it does use cryptography. Hash functions deterministically map arbitrary pieces of data into fixed-length values. It's often easy to compute the hash, but difficult (or impossible) to use the hash to determine the original input. Additionally, cryptographic hash functions cause small changes in the input data to create large changes to the resulting hash values. Hash functions are used for integrity verification, but don't provide an authenticity guarantee.

> "result in large changes to the resulting hash values" - Do we need to say why that's good? Do we need to say hashing is most often used for passwords?
> From some googling, it seems that "authenticity guarantee" may be an industry term, just not one that is frequently used enough for me to get a good sense of its use. I think making it plural does work technically I guess, but it still is pretty awkward to read. Is there some way we can get around this? I changed it to the singular form for now. Below, the term "authenticity protection is used". Is that referring to the same concept as "authenticity guarantees"? Let's make references to this concept consistent.

**Message Authentication Codes** (MACs) combine other cryptographic mechanisms (such as symmetric encryption or hashes) with secret keys to provide both integrity and authenticity protection. However, in order to verify a MAC, multiple entities have to share the same secret key and any of those entities can generate a valid MAC. HMACs, the most commonly used type of MAC, rely on hashing as the underlying cryptographic primitive. The full name of an HMAC algorithm usually includes the underlying hash function's type (for example, HMAC-SHA256 uses the SHA-256 hash function).

**Signatures** combine asymmetric cryptography (that is, using a public/private key pair) with hashing to provide integrity and authenticity by encrypting the hash of the message with the private key. However, unlike MACs, signatures also provide non-repudiation property as the private key should remain unique to the data signer.

**Key Derivation Functions** (KDFs) are often confused with password hashing functions, which are meant for protecting stored passwords for mobile applications. KDFs have many useful properties for password hashing, but were created with different purposes in mind (for example, they are used as components of multiparty key-agreement protocols and to derive keys from secret passwords or passphrases).

### Testing for Insecure and/or Deprecated Cryptographic Algorithms

#### Overview

>Maybe remove these Overview headers? They don't do anything for SEO, and create a double header situation, which is often frowned upon in technical writing. However, I realize this is a book. I'm not sure if there's any similar stigma against double headers in the world of manuals/books. The Overview paragraphs aren't really detailed overviews anyways, often just an introductory paragraph to set things up. 

We should avoid using the many cryptographic algorithms and protocols that have significant, demonstrative weaknesses or are otherwise insufficient for modern security requirements. Algorithms that were considered secure in the past may become insecure over time; therefore, it's important to periodically check current best practices and adjust configurations accordingly.

#### Static Analysis

We can use static analysis to verify that cryptographic algorithms are up to date and inline with industry standards. Algorithms to verify can include outdated block ciphers (such as DES), stream ciphers (such as RC4), hash functions (such as MD5), and broken random number generators (such as Dual_EC_DRBG). Note that even algorithms that are certified (for example, by NIST) can become insecure over time. A certification does not replace periodic verification of an algorithm's soundness. All of these algorithms should be marked as insecure, shouldn't be used, and should be removed from the application code base.

> Unsure about the conclusion of this paragraph. We say these algorithms need to be verified and updated, and then the last sentence says to remove them all? I guess Id like to specify what "all of these algorithms" means. 

First, inspect your app's source code to identify instances of cryptographic algorithms that are known to be weak, such as:

> what source code? I'd like to reword this sentence as a "To do x, do y and then z" but I'm not too sure how. This sounds like the first step of something (that first step being looking for weak algorithms in your app's code maybe?). Is it the first step in a Static Analysis procedure? Above is my attempt based on some of these assumptions.

- [DES, 3DES](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014 "ENISA Algorithms, key size and parameters report 2014")
- RC2
- RC4
- [BLOWFISH](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014 "ENISA Algorithms, key size and parameters report 2014")
- MD4
- MD5
- SHA1

On Android (via Java Cryptography APIs), selecting an algorithm is done by requesting an instance of the `Cipher` (or other primitive) by passing a string containing the algorithm name. For example, `Cipher cipher = Cipher.getInstance("DES");`. On iOS, algorithms are typically selected using predefined constants defined in CommonCryptor.h, e.g., `kCCAlgorithmDES`. Thus, searching the source code for the presence of these algorithm names would indicate that they are used. Note that since the constants on iOS are numeric, an additional check needs to be performed to check whether the algorithm values sent to CCCrypt function map to one of the deprecated/insecure algorithms.

> "selecting an algorithm is done..." <- this is passive voice so I'm having trouble understanding what is going on. I'd like to reword this kinda like "You must select an algorithm to do X (remove it?). To select an algorithm on Android, use a Java Cryptography API to request an instance of the Cipher by passing a string containing the algorithm name" so I'd love help filling in the blanks - do they need any more information to complete this task? (The wording isn't great so far, I'm mostly trying to get all the words down and a basic understanding of what's going on before fixing things more.) I'm also unsure what this is doing - are you just trying to find cryptographic algorithms with this step? or are we removing these algorithms? Similar questions with the iOS part, but I can get to that later. I'd like to change that to "To do X with an algorithm on iOS, ....something something involving CommonCryptor.h to find predefined constants and then searching for them in app source code and doing a check." Lots of blanks to fill in there. 

The following algorithms are recommended:

- Confidentiality algorithms: AES-GCM-256 or ChaCha20-Poly1305
- Integrity algorithms: SHA-256, SHA-384, SHA-512, Blake2
- Digital signature algorithms: RSA (3072 bits and higher), ECDSA with NIST P-384
- Key establishment algorithms: RSA (3072 bits and higher), DH (3072 bits or higher), ECDH with NIST P-384

> recommended for what? to replace the weak algorithms we just searched out? 

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

#### Overview

Choosing a strong cryptographic algorithm alone is not enough. Improper configuration can negatively affect the security of an otherwise sound algorithm. Selecting a proper key length is the most important factor in cryptographic algorithm configuration.

> So, the links above also involve key length. Should this list of resources be moved to the bottom of this chapter? it did feel really weird having references and more resouces in the middle of a chapter. Also, hmm we have a section above on static analysis as well as below....can this all be reorganized and combined? well, the section above was about identifying weak algorithms...and now we are looking at how the good algorithms are configured. is this a sort of step 2 then? first weed out the bad, and now inspect the good for issues?
> what is "used" key length? is this an industry term? having trouble finding information.

#### Static Analysis

Check the source code for any of the following misconfigurations.

##### Insufficient Key Length

Even the most secure encryption algorithm becomes vulnerable to brute-force attacks when that algorithm uses an insufficient key size.

Ensure that used key length fulfills [accepted industry standards](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014 "ENISA Algorithms, key size and parameters report 2014"). Also verify the used [security "Crypto" provider on the Android platform](https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html "Security Crypto provider on the Android platform deprecated in Android N").

> "Also verify the used security Crypto provider on the Android platform" <- verify for what? make sure it's not depreciated?

##### Weak AES Configuration

Advanced Encryption Standard (AES) is the widely accepted standard for symmetric encryption in mobile apps. It's an iterative block cipher that is based on a series of linked mathematical operations. AES performs a variable number of rounds on the input, each of which involve substitution and permutation of the bytes in the input block. Each round uses a 128-bit round key which is derived from the original AES key.

As of this writing, no efficient cryptanalytic attacks against AES have been discovered. However, implementation details and configurable parameters such as mode leave some margin for

###### Weak Block Cipher Mode

Block-based encryption is performed upon discrete input blocks (for example, AES has 128 bit blocks). If the plaintext is larger than the block size, the plaintext is internally split up into blocks of the given input size and encryption is performed on each block. A block cipher mode of operation (or block mode) determines if the result of an encrypted block impacts subsequent encrypted blocks.

> "The so called block mode defines, if the result of one encrypted block has any impact upon subsequently encrypted blocks." <- trying to reword this, not sure how. Is this https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation related to what this sentence is talking about? Updated text above based on this assumption. Maybe spelling it out like that isn't required.
> "The result of one encrypted block" <- Should this just be "if the encryption of one block has any impact..." I am wondering if there is some repetition here.

You shouldn't use [ECB (Electronic Codebook)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29 "Electronic Codebook (ECB)") encryption as this mode divides the input into fixed-size blocks that are encrypted separately using the same secret input key. If multiple divided blocks contain the same plaintext, they will be encrypted into identical ciphertext blocks which makes patterns in data easier to identify. The overall structure of the input will still be recognizable within the resulting encrypted blocks. For example, the image below demonstrates how blocks of the same color create encrypted output that can be used to identify the image.

> the term "secret input key" only shows me 450 results on google. is this an established industry term? I think so maybe? ....wanted to check and make sure

![Electronic Codebook (ECB mode encryption)](Images/Chapters/0x07c/ECB.png)

> not sure this image is necessary - nothing else has an in illustration like this

![Difference of encryption modes](Images/Chapters/0x07c/EncryptionMode.png)

Verify that Cipher Block Chaining (CBC) mode is used instead of ECB. In CBC mode, plaintext blocks are XORed with the previous ciphertext block. This ensures that each encrypted block is unique and randomized even if blocks contain the same information.

When storing encrypted data, we recommend using a block mode that also protects the integrity of the stored data, such as Galois/Counter Mode (GCM). The latter has the additional benefit that the algorithm is mandatory for each TLSv1.2 implementation, and thus is available on all modern platforms.

For more information on effective block modes, see the [NIST guidelines on block mode selection](http://csrc.nist.gov/groups/ST/toolkit/BCM/modes_development.html "NIST Modes Development, Proposed Modes").

###### Predictable Initialization Vector

CBC mode requires the first plaintext block to be combined with an initialization vector (IV). The IV doesn't have to be kept secret, but it shouldn't be predictable. Make sure that IVs are generated using a cryptographically-secure random number generator. For more information on IVs, see [Crypto Fail's initialization vectors article](http://www.cryptofails.com/post/70059609995/crypto-noobs-1-initialization-vectors).

###### Symmetric Encryption with Hard-Coded Cryptographic Keys

The security of symmetric encryption and keyed hashes (MACs) depends on the secrecy of the *Q-* used secret key. If the key is disclosed, the security gained by encryption is lost. To prevent this, never store secret keys in the same place as the encrypted data they helped create. Developers often make the mistake of encrypting locally stored data with a static encryption key and compiling that key into the app. This makes the key accessible to anyone who can use a disassembler.

> Is hard-coded cryptographic key the same as static encryption key? Let's pick one and go with it if so. So with hard-coded keys...the key is included in the code of the app. So what's the alternative? What should they do with it instead? So it should be stored outside the app on the device?

First, ensure that no keys or passwords are hard-coded and stored within the source code. Note that hard-coded keys are problematic even if the source code is obfuscated; obfuscation is easily bypassed by *Q-* dynamic instrumentation and doesn't differ (in principle) from hard coded keys.

If the app is using two-way SSL (both server and client certificates are validated), check if:
    1. The password to the client certificate is not stored locally, or is locked in the device *Q-* Keychain.
    2. The client certificate isn't shared among all installations (for example, hard-coded in the app).

> How is #2 different from the note about hard-coding above? is one a subset of the other?

If the app relies on an additional encrypted containers stored in app data, check how the encryption key is used. If a key-wrapping scheme is used, ensure that the master secret is initialized for each user or the container is re-encrypted with new key. If you can use the master secret or previous password to decrypt the container, check how password changes are handled.

Secret keys must be stored in secure device storage whenever symmertic cryptography is used in mobile apps. For more information on the platform-specific APIs, see the [**Testing Data Storage on Android**](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md) and [**Testing Data Storage on iOS**](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06d-Testing-Data-Storage.md) chapters.

##### Weak Key Generation Functions

Cryptographic algorithms (such as symmetric encryption or MACs) expect a secret input of a given size (for example, 128 or 256 bit). A native implementation might use the user-supplied password directly as an input key. Using a user-supplied password as an input key has the following problems:

- If the password is smaller than the key, the full key space isn't used. The remaining space is padded (spaces are sometimes used for padding).
- A user-supplied password will realistically consist mostly of displayable and pronounceable characters. Therefore, only a subset of all possible ASCII characters are used and entropy is decresed (from 2<sup>8</sup> to approximately 2<sup>6</sup>).
- If two users select the same password, an attacker can match the encrypted files. This makes rainbow table attacks a possibility.

> How can the password be smaller then the key when the password is being used as the key? Maybe I'm just not understanding, or there is some inconsistency with the lead-in paragraph and the first bullet?

Ensure that passwords arn't directly passed into an encryption function. Instead, the user-supplied password should be passed into a salted hash function or KDF to create a cryptographic key. Choose an appropriate iteration count when using password derivation functions. For example, [NIST recommends and iteration count of at least 10,000 for PBKDF2](https://pages.nist.gov/800-63-3/sp800-63b.html#sec5 "NIST Special Publication 800-63B").

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
