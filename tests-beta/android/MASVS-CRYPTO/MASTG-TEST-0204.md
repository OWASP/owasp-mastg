---
platform: android
title: Insecure Random API Usage
id: MASTG-TEST-0204
type: [static]
best-practices: [MASTG-BEST-0001]
prerequisites:
- identify-sensitive-data
- identify-security-relevant-contexts
weakness: MASWE-0027
profiles: [L1, L2]
---

## Overview

Android apps sometimes use an insecure [pseudorandom number generator (PRNG)](../../../Document/0x05e-Testing-Cryptography.md#random-number-generation), such as [`java.util.Random`](https://developer.android.com/reference/java/util/Random), which is a linear congruential generator and produces a predictable sequence for any given seed value. As a result, `java.util.Random` and `Math.random()` ([the latter](https://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/) simply calls `nextDouble()` on a static `java.util.Random` instance) generate reproducible sequences across all Java implementations whenever the same seed is used. This predictability makes them unsuitable for cryptographic or other security-sensitive contexts.

In general, if a PRNG is not explicitly documented as being cryptographically secure, it should not be used where randomness must be unpredictable. Refer to the [Android Documentation](https://developer.android.com/privacy-and-security/risks/weak-prng) and the ["random number generation" guide](../../../Document/0x05e-Testing-Cryptography.md#random-number-generation) for further details.

## Steps

1. Run a static analysis (@MASTG-TECH-0014) tool on the app and look for insecure random APIs, or you can use @MASTG-TECH-0033 to detect the use of such APIs.
2. For each of the identified API uses, check if they are used in a security relevant context. You can decompile the app (@MASTG-TECH-0017) and inspect the code (@MASTG-TECH-0023) to confirm.

## Observation

The output should contain a list of locations where insecure random APIs are used.

## Evaluation

The test case fails if you can find random numbers generated using those APIs that are used in security-relevant contexts, such as generating passwords or authentication tokens.
