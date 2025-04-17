---
title: Correct implementation of server certificate verification
platform: android
id: MASTG-TEST-0234-1
type: [static]
weakness: MASWE-0052
---

## Overview



## Steps

1. Reverse engineer (@MASTG-TECH-0017) the app (@MASTG-APP-0018).
2. Run a static analysis (@MASTG-TECH-0014) tool for the app (@MASTG-APP-0018) and look for all usages of `checkServerTrusted`.

## Observation

You will find two instances of `checkServerTrusted` within the `MainActivity` smali file. There are calls to null checks for each of the parameters `chain` and `authType` as required by the method signature and the invocation of a static log function `w` denoted by `invoke-static`, but there is no indication that a `CertificateException` can be thrown beside an annotation connected to the `checkServerTrusted` method signature.

## Evaluation
