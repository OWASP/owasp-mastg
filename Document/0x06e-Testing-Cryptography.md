# iOS Cryptographic APIs

## Overview

In the ["Mobile App Cryptography"](0x04g-Testing-Cryptography.md) chapter, we introduced general cryptography best practices and described typical issues that can occur when cryptography is used incorrectly. In this chapter, we'll go into more detail on iOS's cryptography APIs. We'll show how to identify usage of those APIs in the source code and how to interpret cryptographic configurations. When reviewing code, make sure to compare the cryptographic parameters used with the current best practices linked from this guide.

### Cryptography Implementations

#### Platform-Provided APIs

Apple provides libraries that include implementations of most common cryptographic algorithms. [Apple's Cryptographic Services Guide](https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html "Apple Cryptographic Services Guide") is a great reference. It contains generalized documentation of how to use standard libraries to initialize and use cryptographic primitives, information that is useful for source code analysis.

Selecting the right API depends on the use case at hand. However, as a rule of thumb you should always prefer the higher-level APIs and libries. But there will be cases where that's not possible, for instance:

- Hash Algorithms: CryptoKit supports SHA256, SHA385, and SHA512, and even SHA1, MD5 via its `Insecure` class. So if the app needs to calculate MD2, MD4, or SHA224, you'll have to use CommonCrypto.
- Asymmetric-Key Algorithms: CryptoKit does not support RSA, so you’ll have to use Security framework via SecKey.
- Symmetric-Key Cryptography: CryptoKit supports AES-GCM only, so if the app needs AES-ECB or AES-CBC, you'll have to use CommonCrypto.
- Random Bit Generation: CryptoKit does not support RBG so you'll have to use CommonCrypto's `SecRandomCopyBytes`.

The [blog post "When CryptoKit is not Enough" by Andrés Ibañez](https://www.andyibanez.com/posts/cryptokit-not-enough/ "When CryptoKit is not Enough") gives a good overview of all options and alternatives.

##### CryptoKit

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

##### CommonCrypto, SecKey and Wrapper Libraries

The most commonly used API for cryptographic operations is CommonCrypto, which is packed with the iOS runtime. The functionality offered by CommonCrypto can best be dissected by having a look at the [source code of the header file](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h.auto.html "CommonCrypto.h"):

- The `CommonCryptor.h` gives the parameters for the symmetric cryptographic operations (AES128, DES, 3DES, CAST, RC4, RC2).
- The `CommonDigest.h` gives the parameters for the hashing Algorithms.
- The `CommonHMAC.h` gives the parameters for the supported HMAC operations.
- The `CommonKeyDerivation.h` gives the parameters for supported KDF functions.
- The `CommonSymmetricKeywrap.h` gives the function used for wrapping a symmetric key with a Key Encryption Key.

Unfortunately, `CommonCryptor.h` lacks a few types of operations in its public APIs, such as: GCM mode is only available in its private APIs See [its source code](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60074/include/CommonCryptorSPI.h "GCM in CC"). For this, an additional binding header is necessary or other wrapper libraries can be used.

##### SecKey

For asymmetric operations, Apple provides [SecKey](https://developer.apple.com/documentation/security/seckey "SecKey"). Apple provides a nice guide in its [Developer Documentation](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/using_keys_for_encryption "Using keys for encryption") on how to use this.

##### Wrapper Libraries

Using Apple's low-level APIs from CommonCrypto or SecKey can get very complex. For this reason, there are some third-party libraries which are wrappers around platform-provided APIs. For instance:

- [IDZSwiftCommonCrypto](https://github.com/iosdevzone/IDZSwiftCommonCrypto "IDZSwiftCommonCrypto")
- [Heimdall](https://github.com/henrinormak/Heimdall "Heimdall")
- [SwiftyRSA](https://github.com/TakeScoop/SwiftyRSA "SwiftyRSA")
- [RNCryptor](https://github.com/RNCryptor/RNCryptor "RNCryptor")
- [Arcane](https://github.com/onmyway133/Arcane "Arcane")

#### Third-Party Libraries

There are various third party libraries available, such as:

- **CJOSE**: With the rise of JWE, and the lack of public support for AES GCM, other libraries have found their way, such as [CJOSE](https://github.com/cisco/cjose "cjose"). CJOSE still requires a higher level wrapping as they only provide a C/C++ implementation.
- **CryptoSwift**: A library in Swift, which can be found at [GitHub](https://github.com/krzyzanowskim/CryptoSwift "CryptoSwift"). The library supports various hash-functions, MAC-functions, CRC-functions, symmetric ciphers, and password-based key derivation functions. It is not a wrapper, but a fully self-implemented version of each of the ciphers. It is important to verify the effective implementation of a function.
- **OpenSSL**: [OpenSSL](https://www.openssl.org/ "OpenSSL") is the toolkit library used for TLS, written in C. Most of its cryptographic functions can be used to do the various cryptographic actions necessary, such as creating (H)MACs, signatures, symmetric- & asymmetric ciphers, hashing, etc. There are various wrappers, such as [OpenSSL](https://github.com/ZewoGraveyard/OpenSSL "OpenSSL") and [MIHCrypto](https://github.com/hohl/MIHCrypto "MIHCrypto").
- **LibSodium**: Sodium is a modern, easy-to-use software library for encryption, decryption, signatures, password hashing and more. It is a portable, cross-compilable, installable, packageable fork of NaCl, with a compatible API, and an extended API to improve usability even further. See [LibSodiums documentation](https://download.libsodium.org/doc/installation "LibSodium docs") for more details. There are some wrapper libraries, such as [Swift-sodium](https://github.com/jedisct1/swift-sodium "Swift-sodium"), [NAChloride](https://github.com/gabriel/NAChloride "NAChloride"), and [libsodium-ios](https://github.com/mochtu/libsodium-ios "libsodium ios").
- **Tink**: A new cryptography library by Google. Google explains its reasoning behind the library [on its security blog](https://security.googleblog.com/2018/08/introducing-tink-cryptographic-software.html "Introducing Tink"). The sources can be found at [Tinks GitHub repository](https://github.com/google/tink "Tink at GitHub").
- **Themis**: [Themis](https://github.com/cossacklabs/themis "Themis") is a library for storage and messaging which uses LibreSSL/OpenSSL engine libcrypto as a dependency. It supports Objective-C and Swift for key generation, secure messaging (e.g. payload encryption and signing), secure storage and setting up a secure session. See [their wiki](https://github.com/cossacklabs/themis/wiki/Objective-C-Howto "Themis wiki") for more details.

**IMPORTANT NOTE:** This is by no means a complete overview of all existing cryptographic libraries nor it's a list of recommended libraries. The app developers are solely responsible for choosing secure and well-maintained libraries.

#### Custom Cryptographic Implementations

An increasing amount of developers have created their own implementation of a cipher or a cryptographic function. This practice is _highly_ discouraged and should be vetted very thoroughly by a cryptography expert if used.

### Key Management

#### Key Storage

##### Avoid Storing Keys by using Key Derivation

Not storing a key at all will ensure that no key material can be dumped. This can be achieved by using a Password Key Derivation function, such as PKBDF-2. Note that if you have a predictable key derivation function based on identifiers which are accessible to other applications, the attacker only needs to find the KDF and apply it to the device in order to find the key.

##### Using the Keychain

When you need to store the key, it is recommended to use the Keychain as long as the protection class chosen is not `kSecAttrAccessibleAlways`. Storing keys in any other location, such as the `NSUserDefaults`, property list files or by any other sink from Core Data or Realm, is usually less secure than using the KeyChain.
Even when the sync of Core Data or Realm is protected by using `NSFileProtectionComplete` data protection class, we still recommend using the KeyChain. See the chapter "[Data Storage on iOS](0x06d-Testing-Data-Storage.md)" for more details.

The KeyChain supports two type of storage mechanisms: a key is either secured by an encryption key stored in the secure enclave or the key itself is within the secure enclave. The latter only holds when you use an ECDH signing key. See the [Apple Documentation](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave "Secure Enclave") for more details on its implementation.

##### Hardcoded Keys

Apps must avoid hardcoding encryption keys, as this would mean that every instance of the application uses the same encryption key. An attacker needs only to do the work once in order to extract the key from the source code (whether stored natively or in Objective-C/Swift). Consequently, the attacker can decrypt any other data that was encrypted by the application.

### Random Number Generation

Apple provides a [Randomization Services](https://developer.apple.com/reference/security/randomization_services "Randomization Services") API, which generates cryptographically secure random numbers (more information about the entropy sources ["Apple Platform Security - Random number generation"](https://support.apple.com/en-gb/guide/security/seca0c73a75b/1/web/1)).

The Randomization Services API uses the `SecRandomCopyBytes` function to generate numbers. This is a wrapper function for the `/dev/random` device file, which provides cryptographically secure pseudorandom values from 0 to 255. Make sure that all random numbers are generated with this API. There is no reason for developers to use a different one.

## Testing for Insecure Cryptography Implementations (MSTG-CRYPTO-2)

### Overview

This test checks if the app uses any potentially insecure cryptographic implementations. You can find more information in section "Cryptography Implementations" in the chapter ["Cryptography for Mobile Apps"](0x04g-Testing-Cryptography.md).

### Static Analysis

First of of check if the app mostly relies on **platform-provided** cryptographic implementations. See section ["Platform-Provided APIs"](#platform-provided-apis) for more information.

Check the list of **third-party** libraries used by the app. You should have a list of them after performing the test in ["Checking for Weaknesses in Third Party Libraries (MSTG-CODE-5)"](0x06i-Testing-Code-Quality-and-Build-Settings.md#checking-for-weaknesses-in-third-party-libraries-mstg-code-5). You can also use the references we provide in section ["Third-Party Libraries"](#third-party-libraries) as a starting point.

Lastly, check if the app has any **custom** cryptographic implementations (aka. _rolls its own crypto_), for instance by searching for well-known cryptographic constants. Pay attention to how data structures holding cryptographic keys and plaintext are defined and how they are cleaned up (wiped or zeroized).

- If the keyword `let` is used, then you create an immutable structure which is harder to wipe from memory.
- Make sure that it is part of a parent structure which can be easily removed from memory (e.g. a `struct` that lives temporally).

## Testing for Common Cryptography Configuration Issues (MSTG-CRYPTO-3)

### Overview

This test focuses on verifying if cryptography primitives are configured and used according to current best practices.

### Static Analysis

Identify all the uses of cryptography within the code.

For all platform-provided APIs found, verify that they follow all platform best practices specified by Apple in its ["Cryptographic Services Guide"](https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/Introduction/Introduction.html) and ["Security Guide - Cryptographic interfaces"](https://developer.apple.com/security "Security").

Ensure that all other general best practices outlined in the "[Cryptography for Mobile Apps](0x04g-Testing-Cryptography.md)" chapter are followed.

### Dynamic Analysis

You can use [method tracing](0x06c-Reverse-Engineering-and-Tampering.md#method-tracing) on cryptographic methods to determine input / output values such as the keys that are being used.

## Testing Key Management (MSTG-CRYPTO-5)

### Static Analysis

There are various keywords to look for: check the libraries mentioned in the overview and static analysis of the section ["Testing for Common Cryptography Configuration Issues"](#testing-for-common-cryptography-configuration-issues-mstg-crypto-3) and make sure that:

- keys are not synchronized over devices if it is used to protect high-risk data.
- keys are not stored without additional protection.
- keys are not hardcoded.
- keys are not derived from stable features of the device.
- keys are not hidden by use of lower level languages (e.g. C/C++).
- keys are not imported from unsafe locations.

Most of the recommendations for static analysis can already be found in chapter "Testing Data Storage for iOS". Next, you can read up on it at the following pages:

- [Apple Developer Documentation: Certificates and keys](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys "Certificates and keys")
- [Apple Developer Documentation: Generating new keys](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys "Generating new keys")
- [Apple Developer Documentation: Key generation attributes](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/key_generation_attributes "Key Generation attributes")

### Dynamic Analysis

Hook cryptographic methods and analyze the keys that are being used. Monitor file system access while cryptographic operations are being performed to assess where key material is written to or read from.

## Testing Random Number Generation (MSTG-CRYPTO-6)

### Overview

This test case focuses on random values used by application. The following checks should be performed:

- identify all instances where random values are used
- verify if random number generators are not considered as being cryptographically secure
- verify how random number generators are used
- verify randomness of the generated random values (optional)

### Static Analysis

Identify all the instances of random number generators and look for either custom or well-known insecure classes. The app should prefer using the recommended APIs such as [`SecRandomCopyBytes`](https://developer.apple.com/reference/security/1399291-secrandomcopybytes "SecRandomCopyBytes (Swift)"). In Swift, it's used as follows:

```swift
var bytes = [Int8](repeating: 0, count: 10)
let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)

if status == errSecSuccess { // Always test the status.
    print(bytes)
    // Prints something different every time you run.
}
```

If the app is using `SecRandomCopyBytes`:

- Check if it uses the default random number generator `kSecRandomDefault` or `NULL`. If not, inspect the code of the provided random number generator.
- Check if the app validates the return value to make sure that the array has been updated with new, random data before trying to use the values.

If other mechanisms are used for random numbers in the code, verify that these are either wrappers around the APIs mentioned above or review them for their secure-randomness.

Note (optional): If you want to test for randomness, you can try to capture a large set of numbers and check with [Burp's sequencer plugin](https://portswigger.net/burp/documentation/desktop/tools/sequencer "Sequencer") to see how good the quality of the randomness is.

### Dynamic Analysis

You can use [method tracing](0x06c-Reverse-Engineering-and-Tampering.md#method-tracing) on the mentioned classes and methods to determine input/output values being used.

## References

### OWASP MASVS

- MSTG-CRYPTO-1: "The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption."
- MSTG-CRYPTO-2: "The app uses proven implementations of cryptographic primitives."
- MSTG-CRYPTO-3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices."
- MSTG-CRYPTO-5: "The app doesn't re-use the same cryptographic key for multiple purposes."
- MSTG-CRYPTO-6: "All random values are generated using a sufficiently secure random number generator."

### General Security Documentation

- Apple Developer Documentation on Security - <https://developer.apple.com/documentation/security>
- Apple Security Guide - <https://www.apple.com/business/site/docs/iOS_Security_Guide.pdf>

### Configuration of Cryptographic algorithms

- Apple's Cryptographic Services Guide - <https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html>
- Apple Developer Documentation on randomization SecKey - <https://opensource.apple.com/source/Security/Security-57740.51.3/keychain/SecKey.h.auto.html>
- Apple Documentation on Secure Enclave - <https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave?language=objc>
- Source code of the header file - <https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h.auto.html>
- GCM in CommonCrypto - <https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60074/include/CommonCryptorSPI.h>
- Apple Developer Documentation on SecKey - <https://opensource.apple.com/source/Security/Security-57740.51.3/keychain/SecKey.h.auto.html>
- IDZSwiftCommonCrypto - <https://github.com/iosdevzone/IDZSwiftCommonCrypto>
- Heimdall - <https://github.com/henrinormak/Heimdall>
- SwiftyRSA - <https://github.com/TakeScoop/SwiftyRSA>
- RNCryptor - <https://github.com/RNCryptor/RNCryptor>
- Arcane - <https://github.com/onmyway133/Arcane>
- CJOSE - <https://github.com/cisco/cjose>
- CryptoSwift - <https://github.com/krzyzanowskim/CryptoSwift>
- OpenSSL - <https://www.openssl.org/>
- LibSodiums documentation - <https://download.libsodium.org/doc/installation>
- Google on Tink - <https://security.googleblog.com/2018/08/introducing-tink-cryptographic-software.html>
- Themis - <https://github.com/cossacklabs/themis>
- cartfile - <https://github.com/Carthage/Carthage/blob/master/Documentation/Artifacts.md#cartfile>
- Podfile - <https://guides.cocoapods.org/syntax/podfile.html>

### Random Number Documentation

- Apple Developer Documentation on randomization - <https://developer.apple.com/documentation/security/randomization_services>
- Apple Developer Documentation on secrandomcopybytes - <https://developer.apple.com/reference/security/1399291-secrandomcopybytes>
- Burp Suite Sequencer - <https://portswigger.net/burp/documentation/desktop/tools/sequencer>

### Key Management

- Apple Developer Documentation: Certificates and keys - <https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys>
- Apple Developer Documentation: Generating new keys - <https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys>
- Apple Developer Documentation: Key generation attributes -
<https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/key_generation_attributes>
