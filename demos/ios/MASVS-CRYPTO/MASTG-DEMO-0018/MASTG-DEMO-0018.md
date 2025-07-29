---
platform: ios
title: Uses of Broken Encryption Algorithms in CommonCrypto with r2
code: [swift]
id: MASTG-DEMO-0018
test: MASTG-TEST-0210
---

### Sample

{{ MastgTest.swift # function.asm # decompiled-o1-review.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Open the app binary with @MASTG-TOOL-0073 with the `-i` option to run this script.

{{ cccrypt.r2 }}

{{ run.sh }}

### Observation

The output contains the disassembled code of the function using `CCCrypt`.

{{ output.txt }}

### Evaluation

Inspect the disassembled code to identify the use of insecure algorithms.

In [CommonCryptor.h](https://web.archive.org/web/20240606000307/https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h) you can find the definition of the `CCCrypt` function:

```c
CCCryptorStatus CCCrypt(
    CCOperation op,         /* kCCEncrypt, etc. */
    CCAlgorithm alg,        /* kCCAlgorithmAES128, etc. */
    CCOptions options,      /* kCCOptionPKCS7Padding, etc. */
    const void *key,
    size_t keyLength,
    const void *iv,         /* optional initialization vector */
    const void *dataIn,     /* optional per op and alg */
    size_t dataInLength,
    void *dataOut,          /* data RETURNED here */
    size_t dataOutAvailable,
    size_t *dataOutMoved);
```

There you will also find the `alg` and the `op`:

```c
/*!
    @enum        CCAlgorithm
    @abstract    Encryption algorithms implemented by this module.

    @constant    kCCAlgorithmAES128    Advanced Encryption Standard, 128-bit block
    @constant    kCCAlgorithmDES        Data Encryption Standard
    @constant    kCCAlgorithm3DES    Triple-DES, three key, EDE configuration
    @constant    kCCAlgorithmCAST    CAST
    @constant    kCCAlgorithmRC4        RC4 stream cipher
*/
enum {
    kCCAlgorithmAES128 = 0,
    kCCAlgorithmDES,
    kCCAlgorithm3DES,
    kCCAlgorithmCAST,
    kCCAlgorithmRC4,
    kCCAlgorithmRC2
};
typedef uint32_t CCAlgorithm;

/*!
    @enum        CCOperation
    @abstract    Operations that an CCCryptor can perform.

    @constant    kCCEncrypt    Symmetric encryption.
    @constant    kCCDecrypt    Symmetric decryption.
*/
enum {
    kCCEncrypt = 0,
    kCCDecrypt,
};
```

With this information we can now inspect the disassembled code and we'll see that the 3DES algorithm (`kCCAlgorithm3DES`) can be found by its numeric value `2` in the second argument of the `CCCrypt` function (`w1`). The `CCCrypt` function is called with a padding option of PKCS7, no initialization vector, and a key of 24 bytes:

{{ evaluation.txt }}

The test fails because the 3DES encryption algorithm was found in the code.

**Note**: Using artificial intelligence we're able to decompile the disassembled code and review it. The output is a human-readable version of the assembly code. The AI decompiled code may not be perfect and might contain errors but, in this case, it clearly shows the use of `CCCrypt` and the associated algorithm.
