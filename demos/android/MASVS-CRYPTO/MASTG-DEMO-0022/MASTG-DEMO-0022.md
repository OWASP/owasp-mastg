---
platform: android
title: Uses of Insecure Encryption Algorithms in Cipher with semgrep
id: MASTG-DEMO-0022
code: [kotlin]
---

### Sample

The code snippet below shows sample code contains use of insecure encryption algorithms.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-weak-encryption-algorithms.yaml }}

{{ run.sh }}

### Observation

The rule has identified two instances in the code file where insecure encryption algorithms are used. The specified line numbers can be located in the reverse-engineered code for further investigation and remediation.

{{ output.txt }}

### Evaluation

The test fails due to the use of weak encryption algorithms, specifically:

- DES (56-bit key, breakable, [withdrawn by NIST in 2005](https://csrc.nist.gov/pubs/fips/46-3/final))
- 3DES (Weak 64-bit blocks, vulnerable to the [Sweet32 Attack](https://sweet32.info/), [withdrawn by NIST on January 1, 2024](https://csrc.nist.gov/pubs/sp/800/67/r2/final))
- RC4 (Biased key stream, allows plaintext recovery [RC4 Weakness](https://www.rc4nomore.com/), disapproved by [NIST](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-52r1.pdf) in 2014 and prohibited by [IETF](https://datatracker.ietf.org/doc/html/rfc7465) in 2015)
