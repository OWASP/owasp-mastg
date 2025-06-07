---
platform: ios
title: Usage of Outdated Code Signature Format
id: MASTG-TEST-0220
type: [static]
weakness: MASWE-0104
profiles: [R]
---

## Overview

On iOS, code signatures verify the integrity and authenticity of an app's binary, preventing unauthorized modifications and ensuring that the app is trusted by the operating system. Apple regularly updates its [code signature formats](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format) to enhance cryptographic strength and improve protection against tampering.

Using an outdated code signature format may expose the app to security risks, as older formats may lack support for current cryptographic standards and may be more vulnerable to manipulation. Adopting the latest code signature format helps maintain app integrity and ensures compatibility with the latest security features in iOS.

## Steps

1. Extract the package as described in @MASTG-TECH-0058.
2. Obtain the version of the code signature format as described in @MASTG-TECH-0112.

## Observation

The output should contain the version of the code signature format.

## Evaluation

The test fails if the version is below the [recommended one](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format "Apple Developer").

Ensure that the app is using the [latest code signing format](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format "Apple Developer"). You can retrieve the signing certificate format with @MASTG-TECH-0112. This will ensure that the integrity of the app is protected according to the latest cryptographic standards, preventing tampering with the app binary and ensuring that the unmodified copy is distributed to users.
