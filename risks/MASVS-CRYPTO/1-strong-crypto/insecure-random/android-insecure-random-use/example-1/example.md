---
platform: android
title: Common Uses of Insecure Random APIs
tools: [semgrep]
code: [java]
---

### Sample

{{ mstg-crypto-6.java }}

### Steps

Let's run our sempgrep rule against the sample code.

{{ ../rules/mstg-crypto-6.yaml }}

{{ run.sh }}

### Observation

The rule has identified five instances in the code file where an insecure random number generator is used. The specified line numbers can be located in the original code for further investigation and remediation.

{{ output.txt }}

### Evaluation

Review each of the reported instances. Some of them seem to be used for testing purposes, as indicated by the function names.

However, the ones on lines 36 and 41 are used to generate random numbers for security purposes, in this case for generating authentication tokens.
