---
platform: android
title: Common Uses of Insecure Random APIs
id: MASTG-DEMO-0007
code: [java]
test: MASTG-TEST-0204
---

### Sample

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-random-apis-insufficient-entropy.yml }}

{{ run.sh }}

### Observation

The rule has identified five instances in the code file where an insecure random number generator is used. The specified line numbers can be located in the original code for further investigation and remediation.

{{ output.txt }}

### Evaluation

Review each of the reported instances.

- Line 12 seems to be used to generate random numbers for security purposes, in this case for generating authentication tokens.
- Line 17 is part of the function `get_random`. Review any calls to this function to ensure that the random number is not used in a security-relevant context.
- Line 27 is part of the password generation function which is a security-critical operation.

Note that line 37 did not trigger the rule because the random number is generated using `SecureRandom` which is a secure random number generator.
