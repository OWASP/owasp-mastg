---
platform: ios
title: Common Uses of Insecure algorithm
tools: [semgrep]
code: [swift]
---

### Sample

{{ insecure_symmetric_aes_alogrithm.swift }}

### Steps

Let's run our semgrep rule against the sample code.

{{ ../rules/mastg-insecure_symmetric_aes_algorithm.yml }}

{{ run.sh }}

### Observation

The rule has identified five instances in the code file where an insecure AES-128 bit algorithm is used. The specified line numbers can be located in the original code for further investigation and remediation.

{{ output.txt }}

### Evaluation

Review each of the reported instances.

- Line 5 using `kCCKeySizeAES128` is a constant representing the size of the an `AES-128` key in bytes.
- Line 10 using `The SymmetricKey(size: .bits128)` initializer creates a symmetric key with a size of 128 bits (16 bytes), suitable for use with AES-128 encryption
