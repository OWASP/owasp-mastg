---
platform: ios
title: Common Uses of Insecure algorithm
tools: [semgrep]
code: [swift]
---

### Sample

{{ weak-key-generation.swift }}

### Steps

Let's run our semgrep rule against the sample code.

{{ ../rules/mastg-weak_key_generation.yml }}

{{ run.sh }}

### Observation

The rule has identified two instances in the code file where an insecure AES-128 bit algorithm is used. The specified line numbers can be located in the original code for further investigation and remediation.

{{ output.txt }}

### Evaluation

Review each of the reported instances.

- Line 4 using `kCCKeySizeAES128` is a constant representing the size of the an `AES-128` key in bytes.
- Line 8 using the `SymmetricKey(size: .bits128)` initializer creates a symmetric key with a size of 128 bits (16 bytes), suitable for use with AES-128 encryption
