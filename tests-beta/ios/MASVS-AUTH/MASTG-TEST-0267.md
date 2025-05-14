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

The output should contain a list of locations where `LAContext.evaluatePolicy` API are used.

## Evaluation

The test fails if an app uses `LAContext.evaluatePolicy` API to authenticate the user.
