---
masvs_v1_id:
- MSTG-CRYPTO-1
- MSTG-CRYPTO-5
masvs_v2_id:
- MASVS-CRYPTO-2
platform: ios
title: Testing Key Management
masvs_v1_levels:
- L1
- L2
profiles: [L2]
status: deprecated
covered_by: [MASTG-TEST-0213, MASTG-TEST-0214]
deprecation_note: New version available in MASTG V2
---

## Overview

## Static Analysis

There are various keywords to look for: check the libraries mentioned in the overview and static analysis of the section "Verifying the Configuration of Cryptographic Standard Algorithms" for which keywords you can best check on how keys are stored.

Always make sure that:

- keys are not synchronized over devices if it is used to protect high-risk data.
- keys are not stored without additional protection.
- keys are not hardcoded.
- keys are not derived from stable features of the device.
- keys are not hidden by use of lower level languages (e.g. C/C++).
- keys are not imported from unsafe locations.

Check also the [list of common cryptographic configuration issues](../../../Document/0x04g-Testing-Cryptography.md#common-configuration-issues).

Most of the recommendations for static analysis can already be found in chapter "Testing Data Storage for iOS". Next, you can read up on it at the following pages:

- [Apple Developer Documentation: Certificates and keys](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys "Certificates and keys")
- [Apple Developer Documentation: Generating new keys](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys "Generating new keys")
- [Apple Developer Documentation: Key generation attributes](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/key_generation_attributes "Key Generation attributes")

## Dynamic Analysis

Hook cryptographic methods and analyze the keys that are being used. Monitor file system access while cryptographic operations are being performed to assess where key material is written to or read from.
