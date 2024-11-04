---
platform: android
title: Insecure Random API Usage
id: MASTG-TEST-0204
type: [static, dynamic]
mitigations:
- android-use-secure-random
prerequisites:
- identify-sensitive-data
- identify-security-relevant-contexts
weakness: MASWE-0027
---

## Overview

Android apps sometimes use insecure pseudorandom number generators (PRNGs) such as `java.util.Random`, which is essentially a linear congruential generator. This type of PRNG generates a predictable sequence of numbers for any given seed value, making the sequence reproducible and insecure for cryptographic use. In particular, `java.util.Random` and `Math.random()` ([the latter](https://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/) simply calling `nextDouble()` on a static `java.util.Random` instance) produce identical number sequences when initialized with the same seed across all Java implementations.
In general, if a PRNG is not advertised as being cryptographically secure, then it is probably a statistical PRNG and should not be used in security-sensitive contexts.

## Steps

1. Run a static analysis (@MASTG-TECH-0014) tool on the app and look for insecure random APIs, or you can use @MASTG-TECH-0033 to detect the use of such APIs.

## Observation

The output should contain a list of locations where insecure random APIs are used.

## Evaluation

The test case fails if you can find random numbers generated using those APIs that are used in security-relevant contexts, such as passwords or tokens.
