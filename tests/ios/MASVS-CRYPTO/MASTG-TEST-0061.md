---
masvs_v1_id:
- MSTG-CRYPTO-2
- MSTG-CRYPTO-3
masvs_v2_id:
- MASVS-CRYPTO-1
platform: ios
title: Verifying the Configuration of Cryptographic Standard Algorithms
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: [MASTG-TEST-0209, MASTG-TEST-0210, MASTG-TEST-0211]
deprecation_note: New version available in MASTG V2
---

## Overview

## Static Analysis

For each of the libraries that are used by the application, the used algorithms and cryptographic configurations need to be verified to make sure they are not deprecated and used correctly.

Pay attention to how-to-be-removed key-holding datastructures and plain-text data structures are defined. If the keyword `let` is used, then you create an immutable structure which is harder to wipe from memory. Make sure that it is part of a parent structure which can be easily removed from memory (e.g. a `struct` that lives temporally).

Ensure that the best practices outlined in the "[Cryptography for Mobile Apps](../../../Document/0x04g-Testing-Cryptography.md)" chapter are followed. Look at [insecure and deprecated algorithms](../../../Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms) and [common configuration issues](../../../Document/0x04g-Testing-Cryptography.md#common-configuration-issues).

### CommonCryptor

If the app uses standard cryptographic implementations provided by Apple, the easiest way to determine the status of the related algorithm is to check for calls to functions from `CommonCryptor`, such as `CCCrypt` and `CCCryptorCreate`. The [source code](https://web.archive.org/web/20240606000307/https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h "CommonCryptor.h") contains the signatures of all functions of CommonCryptor.h. For instance, `CCCryptorCreate` has following signature:

```c
CCCryptorStatus CCCryptorCreate(
    CCOperation op,             /* kCCEncrypt, etc. */
    CCAlgorithm alg,            /* kCCAlgorithmDES, etc. */
    CCOptions options,          /* kCCOptionPKCS7Padding, etc. */
    const void *key,            /* raw key material */
    size_t keyLength,
    const void *iv,             /* optional initialization vector */
    CCCryptorRef *cryptorRef);  /* RETURNED */
```

You can then compare all the `enum` types to determine which algorithm, padding, and key material is used. Pay attention to the keying material: the key should be generated securely - either using a key derivation function or a random-number generation function.
Note that functions which are noted in chapter "Cryptography for Mobile Apps" as deprecated, are still programmatically supported. They should not be used.

### Third party libraries

Given the continuous evolution of all third party libraries, this should not be the place to evaluate each library in terms of static analysis. Still there are some points of attention:

- **Find the library being used**: This can be done using the following methods:
    - Check the [cartfile](https://github.com/Carthage/Carthage/blob/master/Documentation/Artifacts.md#cartfile "cartfile") if Carthage is used.
    - Check the [podfile](https://guides.cocoapods.org/syntax/podfile.html "podfile") if Cocoapods is used.
    - Check the linked libraries: Open the xcodeproj file and check the project properties. Go to the **Build Phases** tab and check the entries in **Link Binary With Libraries** for any of the libraries. See earlier sections on how to obtain similar information using @MASTG-TOOL-0035.
    - In the case of copy-pasted sources: search the headerfiles (in case of using Objective-C) and otherwise the Swift files for known methodnames for known libraries.
- **Determine the version being used**: Always check the version of the library being used and check whether there is a new version available in which possible vulnerabilities or shortcomings are patched. Even without a newer version of a library, it can be the case that cryptographic functions have not been reviewed yet. Therefore we always recommend using a library that has been validated or ensure that you have the ability, knowledge and experience to do validation yourself.
- **By hand?**: We recommend not to roll your own crypto, nor to implement known cryptographic functions yourself.
