---
platform: ios
title: Testing Memory for Sensitive Data
id: MASTG-TEST-0x60
type: [dynamic]
---

## Overview

This test checks if your app retains sensitive data in clear text in memory during runtime. An app should immediately clear and deallocate all sensitive data after use. Sensitive data includes, for example:

- a password a user enters during sign-in
- a credit card number used as a payment method

In this test, we’ll use @MASTG-TOOL-0106 to dump all strings from the app’s memory and identify any sensitive data.

## Steps

1. Open your app
2. Exercise it to trigger storing some information into the memory
3. Run @MASTG-TOOL-0106 on it

## Observation

The output should contain a list of strings present in the runtime.

## Evaluation

The test case fails if you can find the use of any sensitive string

## Mitigation

- If you pass a sensitive data to another function, don't pass it via immutable data types, such as `String` and `NSString`. Use mutable data instead, so that you can overwrite it after use.
- Avoid storing sensitive data inside global variables.
- If you perform modification on sensitive data inside a function, make sure to overwrite all local variables after use.
- Remove the references to sensitive strings immediately after you finish using them.