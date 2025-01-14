---
title: Use Secure Random Number Generator APIs
alias: android-use-secure-random
id: MASTG-BEST-0001
platform: android
---

Use a cryptographically secure pseudorandom number generator as provided by the platform or programming language you are using.

## Java/Kotlin

Use [`java.security.SecureRandom`](https://developer.android.com/reference/java/security/SecureRandom), which complies with the statistical random number generator tests specified in [FIPS 140-2, Security Requirements for Cryptographic Modules, section 4.9.1](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.140-2.pdf) and meets the cryptographic strength requirements described in [RFC 4086: Randomness Requirements for Security](http://tools.ietf.org/html/rfc4086). It produces non-deterministic output and automatically seeds itself during object initialization using system entropy, so manual seeding is generally unnecessary and can weaken randomness if not done properly.

The default (no-argument) constructor of `SecureRandom` is recommended, as it uses the system-provided seed of appropriate length to ensure high entropy. Providing a seed (hardcoded or otherwise) to the constructor is [discouraged in the Android Documentation](https://developer.android.com/privacy-and-security/risks/weak-prng?source=studio#weak-prng-java-security-securerandom), because it risks creating deterministic output and undermining security.

Although [the documentation](https://developer.android.com/reference/java/security/SecureRandom?hl=en#setSeed(byte[])) says the provided seed normally supplements the existing seed, this behavior may differ if an [old security provider](https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html) is used. To avoid these pitfalls, ensure your app targets a modern Android version with an updated provider or explicitly configures a secure provider such as AndroidOpenSSL (or Conscrypt in newer releases).

## Other Languages

Consult the standard library or framework documentation to find the API that exposes the operating system's cryptographically secure pseudorandom number generator. This is usually the safest approach, provided there are no known vulnerabilities in that library's random number generation. For example, see the [Flutter/Dart issue](https://www.zellic.io/blog/proton-dart-flutter-csprng-prng/) as a reminder that some frameworks may have known weaknesses in their PRNG implementations.
