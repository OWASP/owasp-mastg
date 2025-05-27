---
platform: ios
title: Runtime Use Of Event-Bound Biometric Authentication
id: MASTG-TEST-0267
apis: [LAContext.evaluatePolicy]
type: [dynamic]
weakness: MASWE-0044
best-practices: []
---

## Overview

This test is the dynamic counterpart to @MASTG-TEST-0266.

## Steps

1. Run a dynamic analysis tool like @MASTG-TOOL-0039 and look for uses of [LAContext.evaluatePolicy(...)](https://developer.apple.com/documentation/localauthentication/lacontext/evaluatepolicy(_:localizedreason:reply:)).

## Observation

The analysis should output the locations where the `evaluatePolicy` and Keychain APIs are used.

## Evaluation

The test fails if for each sensitive data resource worth protecting:

- `LAContext.evaluatePolicy(...)` is used explicitly.
- There are no calls to `SecAccessControlCreateWithFlags`.
