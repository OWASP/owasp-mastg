---
masvs_category: MASVS-CRYPTO
platform: ios
title: CryptoKit
---

Apple CryptoKit was released with iOS 13 and is built on top of Apple's native cryptographic library corecrypto which is [FIPS 140-2 validated](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3856). The Swift framework provides a strongly typed API interface, has effective memory management, conforms to equatable, and supports generics. CryptoKit contains secure algorithms for hashing, symmetric-key cryptography, and public-key cryptography. The framework can also utilize the hardware based key manager from the Secure Enclave.

Apple CryptoKit contains the following algorithms:

**Hashes:**

- MD5 (Insecure Module)
- SHA1 (Insecure Module)
- SHA-2 256-bit digest
- SHA-2 384-bit digest
- SHA-2 512-bit digest

**Symmetric-Key:**

- Message Authentication Codes (HMAC)
- Authenticated Encryption
    - AES-GCM
    - ChaCha20-Poly1305

**Public-Key:**

- Key Agreement
    - Curve25519
    - NIST P-256
    - NIST P-384
    - NIST P-512

Examples:

Generating and releasing a symmetric key:

```default
let encryptionKey = SymmetricKey(size: .bits256)
```

Calculating a SHA-2 512-bit digest:

```default
let rawString = "OWASP MTSG"
let rawData = Data(rawString.utf8)
let hash = SHA512.hash(data: rawData) // Compute the digest
let textHash = String(describing: hash)
print(textHash) // Print hash text
```

For more information about Apple CryptoKit, please visit the following resources:

- [Apple CryptoKit | Apple Developer Documentation](https://developer.apple.com/documentation/cryptokit "Apple CryptoKit from Apple Developer Documentation")
- [Performing Common Cryptographic Operations | Apple Developer Documentation](https://developer.apple.com/documentation/cryptokit/performing_common_cryptographic_operations "Performing Common Cryptographic Operations from Apple Developer Documentation")
- [WWDC 2019 session 709 | Cryptography and Your Apps](https://developer.apple.com/videos/play/wwdc19/709/ "Cryptography and Your Apps from WWDC 2019 session 709")
- [How to calculate the SHA hash of a String or Data instance | Hacking with Swift](https://www.hackingwithswift.com/example-code/cryptokit/how-to-calculate-the-sha-hash-of-a-string-or-data-instance "How to calculate the SHA hash of a String or Data instance from Hacking with Swift")
