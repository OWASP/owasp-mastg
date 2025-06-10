---
title: Use of Local Storage for Input Validation
platform: android
id: MASTG-TEST-0281
type: [static]
weakness: MASWE-0082
profiles: [L1, L2]
---

## Overview

Android offers `SharedPreferences` for saving key-value pairs of basic data types and strings. When you store structured data like JSON or HTML using `putString()` and `getString()` without adequate validation, it can result in security vulnerabilities such as tampering or injection. This becomes especially dangerous if the stored data is subsequently trusted and utilized directly by the application.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0110 on the code and look for uses of the `putString` and `getString`.

## Observation

The output file shows usages of the input validation using `putString` and `getString` in the code.

## Evaluation

The test fails if the `putString()` and `getString()` was found in the code.
