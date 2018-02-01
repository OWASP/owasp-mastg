## iOS Cryptographic APIs

In the chapter "Testing Cryptography in Mobile Apps", we introduced general cryptography best practices and described typical flaws that can occur when cryptography is used incorrectly in mobile apps. In this chapter, we'll go into more detail on the cryptography APIs available on iOS. We'll show how to identify usage of those APIs in the source code and how to interpret the configuration. When reviewing code, make sure to compare the cryptographic parameters used with the current best practices linked from this guide.

### iOS Cryptography APIs

Apple provides libraries with implementations of most commonly used cryptographic algorithms. A great point of reference is [Apple's Cryptographic Services Guide](https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html "Apple Cryptographic Services Guide"). It contains broad documentation on how to use standard libraries to initialize and use cryptographic primitives, which is also useful when performing source code analysis.

iOS code usually refers to predefined constants defined in `CommonCryptor.h` (for example, `kCCAlgorithmDES`). You can search the source code for these constants to detect if they are used. Note that since the constants on iOS are numeric, make sure to check whether the algorithm constant values sent to the `CCCrypt` function represent an algorithm we know is insecure or deprecated.

If the app is using standard cryptographic implementations provided by Apple, the easiest way is check for calls to functions from `CommonCryptor`, such as `CCCrypt`, `CCCryptorCreate`, etc. The [source code](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h "CommonCryptor.h") contains signatures of all functions. For instance, `CCCryptorCreate` has following signature:

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

You can then compare all the `enum` types to understand which algorithm, padding and key material is being used. Pay attention to the keying material, if it's coming directly from a password (which is bad), or if it's coming from Key Derivation Function (e.g. PBKDF2). Obviously, there are other non-standard libraries that your application might be using (for instance `openssl`), so you should check for these too.

iOS code usually refers to predefined constants defined in `CommonCryptor.h` (for example, `kCCAlgorithmDES`). You can search the source code for these constants to detect if they are used. Note that since the constants on iOS are numeric. Make sure to check whether the algorithm constant values sent to the `CCCrypt` function represent an algorithm we know is insecure or deprecated. Any use of cryptography on iOS should follow the same best practices we described in the chapter [Cryptography in Mobile Apps](0x04g-Testing-Cryptography.md).

### Random Number Generation on iOS

Apple provides developers with the [Randomization Services](https://developer.apple.com/reference/security/randomization_services "Randomization Services") application programming interface (API) that generates cryptographically secure random numbers.

The Randomization Services API uses the `SecRandomCopyBytes` function to perform the numbers generation. This is a wrapper function for the `/dev/random` device file, which provides cryptographically secure pseudorandom value from 0 to 255 and performs concatenation.

Verify that all random numbers are generated using this API - there is no reason why developers should use a different one.

In Swift, the [`SecRandomCopyBytes` API](https://developer.apple.com/reference/security/1399291-secrandomcopybytes "SecRandomCopyBytes (Swift)") is defined as follows:
```
func SecRandomCopyBytes(_ rnd: SecRandomRef?,
                      _ count: Int,
                      _ bytes: UnsafeMutablePointer<UInt8>) -> Int32
```

The [Objective-C version](https://developer.apple.com/reference/security/1399291-secrandomcopybytes?language=objc "SecRandomCopyBytes (Objective-C)") looks as follows:
```
int SecRandomCopyBytes(SecRandomRef rnd, size_t count, uint8_t *bytes);
```

The following is an example of its usage:
```
int result = SecRandomCopyBytes(kSecRandomDefault, 16, randomBytes);
```

### References

#### OWASP Mobile Top 10 2016
- M5 - Insufficient Cryptography - https://www.owasp.org/index.php/Mobile_Top_10_2016-M5-Insufficient_Cryptography

#### OWASP MASVS
- V3.3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices."
- V3.4: "The app does not use cryptographic protocols or algorithms that are widely considered depreciated for security purposes."
- V3.6: "All random values are generated using a sufficiently secure random number generator."

#### CWE
- CWE-337 - Predictable Seed in PRNG
- CWE-338 - Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
