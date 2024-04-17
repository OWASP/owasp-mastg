---
platform: ios
title: Common Uses of Insecure algorithm
tools: [semgrep]
code: [swift]
---

### Sample

{{ weak_symmetric_aes_alogrithm.swift }}

### Steps

Let's run our semgrep rule against the sample code.

{{ ../rules/mastg-weak_symmetric_aes_algorithm.yml }}

{{ run.sh }}

### Observation

The rule has identified five instances in the code file where an insecure AES-128 bit algorithm is used. The specified line numbers can be located in the original code for further investigation and remediation.

{{ output.txt }}

### Evaluation

Review each of the reported instances.

