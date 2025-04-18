---
platform: ios
title: Testing Event-bound Biometric Authentication
id: MASTG-TEST-0266
type: [static]
weakness: MASWE-0044
---

## Overview

This test verifies that your application uses the Keychain API for authentication instead of the less secure LocalAuthentication API. The LocalAuthentication API returns only a boolean result indicating authentication success or failure. This makes it easier to manipulate the logic of the application and skip authentication altogether. Keychain API strengthens the authentication process by returning data from the keychain. This data is essential to continue using the application. For example, it could be a session token for backend API authentication or a cryptographic key to decrypt data from storage. In other words, the Keychain API allows developers to use a more secure architecture instead of relying on a simple if-statement.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary and look for uses of [LAContext.evaluatePolicy(.deviceOwnerAuthentication)](https://developer.apple.com/documentation/localauthentication/lacontext/evaluatepolicy(_:localizedreason:reply:)) API,attribute.

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if an app doesn't use any API to verify the secure screen lock presence.
