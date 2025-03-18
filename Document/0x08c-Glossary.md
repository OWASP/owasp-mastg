---
hide: toc
title: Glossary
---

## Cryptographic Terms

### Broken

The meaning depends on the context.

A "broken" cryptographic hash algorithm is a function that is denounced as "broken" because a collision attack exist that is faster to execute then a birthday attack ([Wikipedia, "2025.02.19"](https://en.wikipedia.org/wiki/Collision_attack "Collision attack")).

An encryption mode of operation is "broken" if it, when implemented correctly, still faces the risk from known attacks that can "break" the confidentiality of the encrypted data.

### Deprecated

When mentioned as a cryptographic term it means a mode of operation, algorithm or cryptographic function that no longer is recommended to be used for certain cryptographic operations. The function may still be recommended for certain cryptographic operations even when deprecated.

### Improper

Used as a catch-all term to cover security behaviors that are either "Missing" or "Insufficient/Incorrect."

### Insufficient

According to MITRE. A general term used to describe when a security property or behavior can vary in strength on a continuous or sliding scale, instead of a discrete scale. The continuous scale may vary depending on the context and risk tolerance. For example, the requirements for randomness may vary between a random selection for a greeting message versus the generation of a military-strength key. On the other hand, a weakness that allows a buffer overflow is always incorrect - there is not a sliding scale that varies across contexts ([MITRE, "2024.07.07"](https://cwe.mitre.org/documents/glossary/index.html#Insufficient "Glossary")).

### Risk

Reference to risk uses the ISO 3000 defnition: Risk = "effect of uncertainty on objectives."

### Risky

A "risky" cryptographic hash algorithm carries with it an effect of uncertainty on the objectives that the specific algorithm must satisfy. The algorithm is therefore said to be "risky" when used under certain circumstances, and because of that, carries with it the risk of being compromised in an attack when used improperly. The same can be considered when referring to a "risky" encryption mode of operation.

### Strength

According to NIST. A number associated with the amount of work (that is, the number of operations) that is required to break a cryptographic algorithm or system. If 2N execution operations of the algorithm (or system) are required to break the cryptographic algorithm, then the security strength is N bits ([NIST, security strength](https://csrc.nist.gov/glossary/term/security_strength "security strength")).
