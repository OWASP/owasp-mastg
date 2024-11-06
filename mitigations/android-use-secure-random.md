---
title: Use Secure Random Number Generators APIs
platform: android
---

[`java.security.SecureRandom`](https://developer.android.com/reference/java/security/SecureRandom) uses SHA1PRNG by default to produce non-deterministic results from a seed based on system thread timing obtained from `dev/urandom`. This seeding occurs automatically during object construction or acquisition, eliminating the need for explicit seeding of the PRNG.

The default [no-argument constructor of `SecureRandom`](https://wiki.sei.cmu.edu/confluence/display/java/MSC02-J.+Generate+strong+random+numbers "Generation of Strong Random Numbers") is usually recommended for generating secure random values, as it uses the system-specified seed value to generate a 128-byte-long random number.

Providing an hard coded seed to the constructor of `SecureRandom` is [discouraged in Android Documentation](https://developer.android.com/privacy-and-security/risks/weak-prng?source=studio#weak-prng-java-security-securerandom), as it may lead to introducing deterministic behavior of  `SecureRandom` in some implementations.
`SecureRandom` documentation explains that [the provided seed supplements, rather than replacing the existing seed](https://developer.android.com/reference/java/security/SecureRandom?hl=en#setSeed(byte[])), but this may not apply if an [old security provider](https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html) is being used.
