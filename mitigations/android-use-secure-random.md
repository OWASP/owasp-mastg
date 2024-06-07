---
title: Use Secure Random Number Generators APIs
platform: android
---

[`java.security.SecureRandom`](https://developer.android.com/reference/java/security/SecureRandom) uses SHA1PRNG by default to produce non-deterministic results from a seed based on system thread timing obtained from `dev/urandom`. This seeding occurs automatically during object construction or acquisition, eliminating the need for explicit seeding of the PRNG.

The default constructor is usually sufficient for generating secure random values. However, while other constructors are available for advanced use cases, their improper use could reduce the randomness of the output. Therefore, non-default constructors should be used with caution.
