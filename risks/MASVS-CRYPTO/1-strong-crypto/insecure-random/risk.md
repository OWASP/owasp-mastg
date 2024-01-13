---
title: Cryptographically Weak Pseudo-Random Number Generator (PRNG)
platform: ["android", "ios"]
profiles: ["L1", "L2"]
mappings:
- masvs-v1: [MSTG-CRYPTO-6]
- masvs-v2: [MASVS-CRYPTO-1]
- cwe:
    - id: 338
      title: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
    - id: 337
      title: Predictable Seed in Pseudo-Random Number Generator (PRNG)
- android: https://developer.android.com/privacy-and-security/risks/weak-prng
observed_examples: 
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-6386
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3419
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4102
impact:
- Bypass Protection Mechanism
mitigations:
- android-use-secure-random
---

## Overview

A pseudorandom number generator (PRNG) algorithm generates sequences based on a seed that may be predictable. Common implementations are not cryptographically secure. For example, they typically use a linear congruential formula, allowing an attacker to predict future outputs, given enough observed outputs. Therefore, it is not suitable for security-critical applications or protecting sensitive data.

## Impact

- Bypass Protection Mechanism: Using a non-cryptographically secure PRNG in a security context, such as authentication, poses significant risks. An attacker could potentially guess the generated numbers and gain access to privileged data or functionality. Predicting or regenerating random numbers can lead to encryption breaches, compromise sensitive user information, or enable user impersonation.

## Mitigations

For security relevant contexts, use cryptographically secure random numbers.

In general, it is strongly recommended not to use any random function on a deterministic way, even if it's a secure one, especially those involving hardcoded seed values (which are vulnerable to exposure by decompilation).

Refer to the [RFC 1750 - Randomness Recommendations for Security](https://www.ietf.org/rfc/rfc1750.txt) and the [OWASP Cryptographic Storage Cheat Sheet  - Secure Random Number Generation](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation) for more information and recommendations on random number generation.
