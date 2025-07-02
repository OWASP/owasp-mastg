---
masvs_v1_id:
- MSTG-CRYPTO-1
masvs_v2_id:
- MASVS-CRYPTO-1
platform: android
title: Testing Symmetric Cryptography
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: ['MASTG-TEST-0212', 'MASTG-TEST-0221']
deprecation_reason: New version available in MASTG V2
---

## Overview

## Static Analysis

Identify all the instances of symmetric key encryption in code and look for any mechanism which loads or provides a symmetric key. You can look for:

- symmetric algorithms (such as `DES`, `AES`, etc.)
- specifications for a key generator (such as `KeyGenParameterSpec`, `KeyPairGeneratorSpec`, `KeyPairGenerator`, `KeyGenerator`, `KeyProperties`, etc.)
- classes importing `java.security.*`, `javax.crypto.*`, `android.security.*`, `android.security.keystore.*`

Check also the [list of common cryptographic configuration issues](../../../Document/0x04g-Testing-Cryptography.md#common-configuration-issues).

For each identified instance verify if the used symmetric keys:

- are not part of the application resources
- cannot be derived from known values
- are not hardcoded in code

For each hardcoded symmetric key, verify that is not used in security-sensitive contexts as the only method of encryption.

As an example we illustrate how to locate the use of a hardcoded encryption key. First disassemble and decompile (@MASTG-TECH-0017) the app to obtain Java code, e.g. by using @MASTG-TOOL-0018.

Now search the files for the usage of the `SecretKeySpec` class, e.g. by simply recursively grepping on them or using jadx search function:

```bash
grep -r "SecretKeySpec"
```

This will return all classes using the `SecretKeySpec` class. Now examine those files and trace which variables are used to pass the key material. The figure below shows the result of performing this assessment on a production ready application. We can clearly locate the use of a static encryption key that is hardcoded and initialized in the static byte array `Encrypt.keyBytes`.

<img src="Images/Chapters/0x5e/static_encryption_key.png" width="600px"/>

## Dynamic Analysis

You can use @MASTG-TECH-0033 on cryptographic methods to determine input / output values such as the keys that are being used. Monitor file system access while cryptographic operations are being performed to assess where key material is written to or read from. For example, monitor the file system by using the [API monitor](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security#8-api-monitor---android-only) of @MASTG-TOOL-0037.
