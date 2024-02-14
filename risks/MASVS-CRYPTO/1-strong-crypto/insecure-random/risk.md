---
title: Cryptographically Weak Pseudo-Random Number Generator (PRNG)
alias: insecure-random
platform: ["android", "ios"]
profiles: ["L1", "L2"]
mappings:
- masvs-v1: [MSTG-CRYPTO-6]
- masvs-v2: [MASVS-CRYPTO-1]
- cwe: [338, 337]
- android: https://developer.android.com/privacy-and-security/risks/weak-prng
observed_examples: 
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-6386
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3419
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4102
---

## Overview

A [pseudorandom number generator (PRNG)](https://en.wikipedia.org/wiki/Pseudorandom_number_generator) algorithm generates sequences based on a seed that may be predictable. Common implementations are not cryptographically secure. For example, they typically use a linear congruential formula, allowing an attacker to predict future outputs, given enough observed outputs. Therefore, it is not suitable for security-critical applications or protecting sensitive data.

## Impact

- **Bypass Protection Mechanism**: Using a non-cryptographically secure PRNG in a security context, such as authentication, poses significant risks. An attacker could potentially guess the generated numbers and gain access to privileged data or functionality. Predicting or regenerating random numbers can lead to encryption breaches, compromise sensitive user information, or enable user impersonation.

## Modes of Introduction

- **Insecure Random APIs**: The app may use many existing APIs to generate random numbers insecurely.
- **Non-random Sources**: The app may use custom methods to create "supposedly random" values, using non-random sources such as the current time.

## Mitigations

For security relevant contexts, use cryptographically secure random numbers.

In general, it is strongly recommended not to use any random function in a deterministic way, even if it's a secure one, especially those involving hardcoded seed values (which are vulnerable to exposure by decompilation).

Refer to the [RFC 1750 - Randomness Recommendations for Security](https://www.ietf.org/rfc/rfc1750.txt) and the [OWASP Cryptographic Storage Cheat Sheet  - Secure Random Number Generation](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation) for more information and recommendations on random number generation.
