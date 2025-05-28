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

1. Use runtime method hooking (see @MASTG-TECH-0095) and look for uses of [LAContext.evaluatePolicy(...)](https://developer.apple.com/documentation/localauthentication/lacontext/evaluatepolicy(_:localizedreason:reply:)).

## Observation

The output should contain a list of locations where `LAContext.evaluatePolicy` function is called including all used flags.

## Evaluation

The test fails if for each sensitive data resource worth protecting:

- `LAContext.evaluatePolicy` is used explicitly.
- There are no calls to `SecAccessControlCreateWithFlags`.
