---
title: Use Secure Random Number Generators APIs
platform: android
---

[`java.security.SecureRandom`](https://developer.android.com/reference/java/security/SecureRandom) uses SHA1PRNG by default to produce non-deterministic results from a seed based on system thread timing obtained from `dev/urandom`. This seeding occurs automatically during object construction or acquisition, eliminating the need for explicit seeding of the PRNG.

The default [no-argument constructor of `SecureRandom`](https://wiki.sei.cmu.edu/confluence/display/java/MSC02-J.+Generate+strong+random+numbers "Generation of Strong Random Numbers") is usually sufficient for generating secure random values, as it uses the system-specified seed value to generate a 128-byte-long random number.
