---
platform: ios
title: Uses of Insufficient Key Size in SecKeyCreateRandomKey with r2
code: [swift]
id: MASTG-DEMO-0011
test: MASTG-TEST-0209
---

### Sample

The following sample demonstrates the use of `SecKeyCreateRandomKey` to generate an RSA key pair with a 1024-bit key size. The key pair is then used to sign and verify a message.

{{ MastgTest.swift }}

### Steps

When calling [`SecKeyCreateRandomKey`](https://developer.apple.com/documentation/security/1823694-seckeycreaterandomkey) the key size is specified in the [`kSecAttrKeySizeInBits`](https://developer.apple.com/documentation/security/ksecattrkeysizeinbits) attribute within the `parameters` dictionary. See [Key Generation Attributes](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/key_generation_attributes) for details.

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Open the app binary with @MASTG-TOOL-0073 with the `-i` option to run this script.

{{ security_keysize.r2 }}

{{ run.sh }}

### Observation

The output contains the disassembled code of the function using `SecKeyCreateRandomKey`.

{{ output.txt }}

This function is pretty big so we just included the relevant part of the code that's right before the call to `SecKeyCreateRandomKey`. Note that we can see attributes being set in the `parameters` dictionary such as `kSecAttrKeySizeInBits` as `reloc.kSecAttrKeySizeInBits`. In radare2, this means that the symbol `kSecAttrKeySizeInBits` is not directly referenced by an absolute address but rather through a relocation entry. This entry will be resolved by the dynamic linker at runtime to the actual address where `kSecAttrKeySizeInBits` is located in memory.

### Evaluation

In the output we can see how the `kSecAttrKeySizeInBits` attribute is set to `1024` bits (0x400 in hexadecimal) using the `x8` register. This is later used to call `SecKeyCreateRandomKey`.

{{ evaluation.txt }}

The test fails because the key size is set to `1024` bits, which is considered insufficient for RSA encryption. The key size should be increased to `2048` bits or higher to provide adequate security against modern cryptographic attacks.
