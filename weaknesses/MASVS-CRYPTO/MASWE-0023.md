---
title: Weak Padding
id: MASWE-0023
alias: weak-padding
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-4]
  masvs-v2: [MASVS-CRYPTO-1]
  mastg-v1: [MASTG-TEST-0014]
  cwe: [208, 325, 327, 780]

refs:
- https://developer.android.com/privacy-and-security/cryptography#deprecated-functionality
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf
- https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile
- https://www.usenix.org/legacy/event/woot10/tech/full_papers/Rizzo.pdf
- https://capec.mitre.org/data/definitions/463.html
- https://robertheaton.com/2013/07/29/padding-oracle-attack/
- https://cryptopals.com/sets/3/challenges/17
- https://medium.com/@masjadaan/oracle-padding-attack-a61369993c86
status: new
---

## Overview

**Outdated or weak padding schemes** can leave mobile apps susceptible to [padding oracle attacks](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Rizzo.pdf), a type of side-channel exploit that lets attackers decrypt or manipulate data **without** knowing the key. These attacks arise when the app reveals whether a padding error occurred (through error messages or timing differences), creating an **oracle**. By submitting modified ciphertexts and observing the app's response, an attacker can gradually recover plaintext or forge ciphertext, compromising both confidentiality and integrity.

Below are two common examples of cryptographic contexts where weak padding can become a problem:

- **Symmetric Cryptography**: In block cipher modes (e.g., AES-CBC), **PKCS#7 padding** is widely used. It becomes vulnerable to padding oracle attacks if the system leaks detailed error messages or timing differences. To mitigate this, cryptographers often use **authenticated encryption modes** like AES-GCM or pair AES-CBC with a separate integrity check (e.g., HMAC in an Encrypt-then-MAC scheme).
- **Asymmetric Cryptography**: With RSA, **PKCS#1 v1.5** is known to be susceptible to attacks such as [Bleichenbacher](https://link.springer.com/content/pdf/10.1007/BFb0055716.pdf) (based on padding oracles). This older scheme is now discouraged or disallowed by various standards (for example, see [RFC 8017, Section 7.2](https://datatracker.ietf.org/doc/html/rfc8017#section-7.2) from November 2016 or [NIST SP 800-131A Rev.2, Section 6](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf) from March 2019).

However, simply using a weak padding scheme does not guarantee a padding oracle vulnerability. As mentioned above, the app must **also** leak information (the "oracle") that indicates whether a padding error has occurred. If both conditions are met, attackers can use these signals to recover sensitive data or to craft malicious ciphertext.

## Impact

- **Loss of Integrity**: Attackers can modify ciphertext, exploiting the padding oracle to trick the system into accepting maliciously altered data, leading to unauthorized data modifications.
- **Loss of Confidentiality**: Attackers can use the padding oracle to iteratively decrypt sensitive information, such as passwords or session tokens, leading to exposure of confidential data.

## Modes of Introduction

- **Insecure Padding for Symmetric Encryption**: Using padding schemes like PKCS#7 without additional message authentication (e.g., HMAC) for symmetric encryption algorithms like AES in block cipher modes (e.g., CBC).
- **Insecure Padding for Asymmetric Encryption**: Using weak padding schemes like PKCS#1 v1.5 for RSA asymmetric encryption.

## Mitigations

- **Use Authenticated Symmetric Encryption Modes**: Prefer authenticated encryption modes like AES-GCM, which eliminate the need for separate padding validation and incorporate integrity checks. If AES-CBC must be used, adopt the Encrypt-then-MAC paradigm (e.g., append HMAC). See [NIST SP 800-175B Rev.1, Section 4.3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175Br1.pdf).
- **Use Secure Padding Schemes for Asymmetric Encryption**: Replace weak schemes like PKCS#1 v1.5 with secure ones such as OAEP (Optimal Asymmetric Encryption Padding). See [NIST SP 800-56B Rev.2, Section 7.2.2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf).
- **Don't Expose Cryptographic Errors**: Do not expose cryptographic error messages, such as padding errors, to users. This prevents attackers from gaining clues about the padding's correctness.
