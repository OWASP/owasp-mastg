---
platform: ios
title: Common Uses of Insecure algorithm
tools: [semgrep]
code: [swift]
id: MASTG-DEMO-0010
test: MASTG-TEST-0209
---

### Sample

{{ MastgTest_keylength.swift }}

### Steps

Let's run our semgrep rule against the sample code.

{{ ../../../../rules/mastg-ios-weak_key_generation.yml }}

{{ run.sh }}

### Observation

The rule has identified two instances in the code file where an insecure 3DES algorithm is used. The specified line numbers can be located in the original code for further investigation and remediation.

{{ output.txt }}

### Evaluation

Review each of the reported instances.

- Line 3 using `kCCAlgorithm3DES` creates a symmetric key with a size of 168 bit.
