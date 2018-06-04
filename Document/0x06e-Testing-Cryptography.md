## iOS Cryptography APIs

In the "Cryptography for Mobile Apps" chapter, we introduced general cryptography best practices and described typical problems that may occur when cryptography is used incorrectly. In this chapter, we'll detail the cryptography APIs available for iOS. We'll show how to identify usage of those APIs in the source code and how to interpret cryptographic configurations. When you're reviewing code, compare the cryptographic parameters with the current best practices linked in this guide.

### iOS Cryptography Libraries

Apple provides libraries that include implementations of most common cryptographic algorithms. [Apple's Cryptographic Services Guide](https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html "Apple Cryptographic Services Guide") is a great reference. It contains generalized documentation of how to use standard libraries to initialize and use cryptographic primitives, information that is useful for source code analysis.

iOS code usually refers to constants defined in `CommonCryptor.h` (for example, `kCCAlgorithmDES`). You can search the source code for these constants to detect their use. Because iOS constants are numeric, you should determine whether the constants sent to the `CCCrypt` function represent an insecure or deprecated algorithm.

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

### Random Number Generation on iOS

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

### References

#### OWASP Mobile Top 10 2016
- M5 - Insufficient Cryptography - https://www.owasp.org/index.php/Mobile_Top_10_2016-M5-Insufficient_Cryptography

#### OWASP MASVS
- V3.3: "The app uses cryptographic primitives that are appropriate for the particular use case, configured with parameters that adhere to industry best practices."
- V3.4: "The app does not use cryptographic protocols or algorithms that are widely considered depreciated for security purposes."
- V3.6: "All random values are generated using a sufficiently secure random number generator."

#### CWE
- CWE-337 - Predictable Seed in PRNG
- CWE-338 - Use of Cryptographically Weak Pseudo Random Number Generator (PRNG)
