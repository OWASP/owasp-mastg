---
platform: ios
title: Usage of Recent Code Signature Format
id: MASTG-TEST-0220
type: [static]
weakness: MASWE-0104
---

## Overview

Ensure that the app is using the [latest code signature format](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format "Apple Developer"). You can retrieve the signing certificate format with @MASTG-TECH-0112.

This ensures that the app's integrity is protected according to recent cryptographic standards. These prevent tampering with the app's binary, ensuring that the unmodified copy is distributed to users.

## Steps

1. Extract the package as described in @MASTG-TECH-0058.
2. Obtain the version of the code signature format as described in @MASTG-TECH-0112.

## Observation

The output should contain the version of the code signature format.

## Evaluation

The test fails if the version is below the [recommended one](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format "Apple Developer").
