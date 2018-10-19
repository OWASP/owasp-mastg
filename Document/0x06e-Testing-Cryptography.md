## iOS Cryptography APIs

In the "Cryptography for Mobile Apps" chapter, we introduced general cryptography best practices and described typical problems that may occur when cryptography is used incorrectly. In this chapter, we'll detail the cryptography APIs available for iOS. We'll show how to identify usage of those APIs in the source code and how to interpret cryptographic configurations. When you're reviewing code, compare the cryptographic parameters with the current best practices linked in this guide.

### Verifying the Configuration of Cryptographic Standard Algorithms

#### Overview
Apple provides libraries that include implementations of most common cryptographic algorithms. [Apple's Cryptographic Services Guide](https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html "Apple Cryptographic Services Guide") is a great reference. It contains generalized documentation of how to use standard libraries to initialize and use cryptographic primitives, information that is useful for source code analysis.

##### CommonCrypto, SecKeyEncrypt and Wrapper libraries
The most commonly used Class for cyrptographic operations is the CommonCrypto, which is packed with the iOS runtime. The functionality offered by the CommonCrypto object can best be disected by having a look at the [source code of the headerile ](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCrypto.h "CommonCrypto.h"):
- The `Commoncryptor.h` gives the parameters for the symmetric cryptographic operations,
- The `CommonDigest.h` gives the parameters for the hashing Algorithms
- The `CommonHMAC.h` gives the parameters for the supported HMAC operations.
- The `CommonKeyDerivation.h` gives the parameters for supported KDF functions
- The `CommonSymmetricKeywrap.h` gives the function used for wrappnig a symmetric key with a Key Encryption Key.

CommonCryptor lacks a few type of operations unfortunately in its public APIs, for instance: GCM mode is only available in its private APIs: see [its sourcecode](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60074/include/CommonCryptorSPI.h "GCM in CC"). For this, an additional binding header is necessary or other wrapper libraries can be used.

Next, for asymmetric operations, Apple provides [SecKey](https://opensource.apple.com/source/Security/Security-57740.51.3/keychain/SecKey.h.auto.html "SecKey"). Apple provides a nice guide in its [Developer Documentation](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/using_keys_for_encryption?language=objc "Using keys for encryption") on how to use this. <TODO: ADD SHORTCOMMINGS IN STATIC ANALYSIS!>

As noted before: there are some wrapper-libraries around for both in order to provide convinience. Typical libraries that are often used are, for instance [IDZSwiftCommonCrypto](https://github.com/iosdevzone/IDZSwiftCommonCrypto "IDZSwiftCommonCrypto") and [SwiftSSL](https://github.com/SwiftP2P/SwiftSSL "SwiftSSL"). Another popular wrapper library which provides additional functionalities is [RNCryptor](https://github.com/RNCryptor/RNCryptor "RNCryptor").

##### Third party libraries
There are various third party libraries available, such as:
- CJOSE: With the rise of JWE, and the lack of public support for AES GCM, other libraries have found their way, such as [CJOSE](https://github.com/cisco/cjose "cjose"). CJOSE still requires a higher level wrapping as they only provide a C/C++ implementation.
- CryptoSwift: https://github.com/krzyzanowskim/CryptoSwift

##### OpenSSL and Wrapper libraries
https://github.com/ZewoGraveyard/OpenSSL


#### Sodium and Wrapper libraries
https://github.com/jedisct1/swift-sodium
https://download.libsodium.org/doc/


####Tink?
https://security.googleblog.com/2018/08/introducing-tink-cryptographic-software.html

##### Themis
[Themis](https://github.com/cossacklabs/themis "Themis") is a wrapper around OpenSSL and provides support for <TODO FIRTHER ELABORATE N IT: https://github.com/cossacklabs/themis/wiki/Objective-C-Howto!








##### Other altiernatives
There are many other libraries, such as [CocoaSecurity](https://github.com/kelp404/CocoaSecurity "CocoaSecurity") and [aerogear-ios-crypto](https://github.com/aerogear/aerogear-ios-crypto "Aerogera-ios-crypto") which are no longer maintained, but do provide support for a set of cyrptographic operations. Like always, it is recommended to look for supported and maintained libraries.


#### Static Analysis

#####CommonCryptor <todo explain which parameters are really old and should not be used!>
If the app uses standard cryptographic implementations provided by Apple, the easiest way to determine the status of the related algorithm is to check for calls to functions from `CommonCryptor`, such as `CCCrypt` and `CCCryptorCreate`. The [source code](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h "CommonCryptor.h") contains the signatures of all functions of CommonCryptor.h. For instance, `CCCryptorCreate` has following signature:

```
CCCryptorStatus CCCryptorCreate(
	CCOperation op,             /* kCCEncrypt, etc. */
	CCAlgorithm alg,            /* kCCAlgorithmDES, etc. */
	CCOptions options,          /* kCCOptionPKCS7Padding, etc. */
	const void *key,            /* raw key material */
	size_t keyLength,
	const void *iv,             /* optional initialization vector */
	CCCryptorRef *cryptorRef);  /* RETURNED */
```

You can then compare all the `enum` types to determine which algorithm, padding, and key material is used. Pay attention to the keying material, nothing whether it's coming directly from a password (which is bad) or from a Key Derivation Function (e.g., PBKDF2). Obviously, your application may use other non-standard libraries (`openssl`, for example), so look for those too.

iOS code usually references predefined constants that are defined in `CommonCryptor.h` (for example, `kCCAlgorithmDES`). You can search the source code for these constants. iOS cryptography should be based on the best practices described in the chapter "Cryptography for Mobile Apps."




#### Dynamic Analysis

### Testing Random Number Generation

#### OVerview (TODO: RECREATE STUFF TO THE SAME CHAPTER LAY-OUT!)

#### Static Analysis (TODO: RECREATE STUFF TO THE SAME CHAPTER LAY-OUT!)

#### Dynamic Analysis (TODO: RECREATE STUFF TO THE SAME CHAPTER LAY-OUT!)

Apple provides a [Randomization Services](https://developer.apple.com/reference/security/randomization_services "Randomization Services") API, which generates cryptographically secure random numbers.

The Randomization Services API uses the `SecRandomCopyBytes` function to generate numbers. This is a wrapper function for the `/dev/random` device file, which provides cryptographically secure pseudorandom values from 0 to 255. Make sure that all random numbers are generated with this API-there is no reason for developers to use a different one.

In Swift, the [`SecRandomCopyBytes` API](https://developer.apple.com/reference/security/1399291-secrandomcopybytes "SecRandomCopyBytes (Swift)") is defined as follows:
```
func SecRandomCopyBytes(_ rnd: SecRandomRef?,
                      _ count: Int,
                      _ bytes: UnsafeMutablePointer<UInt8>) -> Int32
```

The [Objective-C version](https://developer.apple.com/reference/security/1399291-secrandomcopybytes?language=objc "SecRandomCopyBytes (Objective-C)") is
```
int SecRandomCopyBytes(SecRandomRef rnd, size_t count, uint8_t *bytes);
```

The following is an example of the APIs usage:
```
int result = SecRandomCopyBytes(kSecRandomDefault, 16, randomBytes);
```

### Testing Key Management (TODO: implement (#922)!)

#### OVerview (TODO: implement (#922)!)
There are various methods on how to store the key on the device. Storing the key in the Keychain is highly recommended, as long as the .
Obviously, alternatives can be chosen, such as using a PWKDF function in order to use a password from the user to generate a key. Storing keys in any other location, such as the `NSUserDefaults`, Propertylists or by any other sink from Coredata, is often not a good idea. If `CoreData` is used, then at least ensure that the sink (often a SQLite Database) is using the `NSFileProtectionComplete` data protection class. See the Testing Data Storage section for more details.

 the filesystem (in terms of a SQLite database or a Realm database) is never a good idea.
Background: https://www.apple.com/business/site/docs/iOS_Security_Guide.pdf
Managing keys: https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys
https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys?language=objc
#### Static Analysis (TODO: implement (#922)!)

#### Dynamic Analysis (TODO: implement (#922)!)

### References

#### Random Number Documentation
- https://developer.apple.com/documentation/security/randomization_services
- https://developer.apple.com/reference/security/1399291-secrandomcopybytes

#### General Security Documentation:
- https://developer.apple.com/documentation/security
- https://www.apple.com/business/site/docs/iOS_Security_Guide.pdf

#### OWASP Mobile Top 10 2016
- M5 - Insufficient Cryptography - https://www.owasp.org/index.php/Mobile_Top_10_2016-M5-Insufficient_Cryptography

#### OWASP MASVS
- V3.3: "The app uses cryptographic primitives that are appropriate for the particular use case, configured with parameters that adhere to industry best practices."
- V3.4: "The app does not use cryptographic protocols or algorithms that are widely considered depreciated for security purposes."
- V3.6: "All random values are generated using a sufficiently secure random number generator."

#### CWE
- CWE-337 - Predictable Seed in PRNG
- CWE-338 - Use of Cryptographically Weak Pseudo Random Number Generator (PRNG)
