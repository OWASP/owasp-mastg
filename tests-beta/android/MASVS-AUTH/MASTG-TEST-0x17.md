---
platform: android
title: Insecure Implementation of Confirm Credentials
id: MASTG-TEST-0x017
type: [static, dynamic]
weakness: MASWE-0034
---

## Overview

The ["Confirm Credential Flow"](../../../Document/0x05f-Testing-Local-Authentication.md#confirm-credential-flow) (since Android 6.0) is a convenience feature to reduce the number of times that a user has to authenticate to the device (e.g. via biometrics). It allows the app to unlock cryptographic materials from the `AndroidKeystore` whenever users unlocked the device within the set time limits (`setUserAuthenticationValidityDurationSeconds`), otherwise the device needs to be unlocked again.

If the app simply checks whether the user has unlocked a key or not, but the key is not actually used, e.g. to decrypt local storage or a message received from a remote endpoint, the app may be vulnerable to a local authentication bypass.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0014)
2. Search for uses of ConfirmCredentials and `setUserAuthenticationValidityDurationSeconds`.

## Observation

The output should contain the reverse engineered code that uses Confirm Credential.

## Evaluation

The test case fails if the app does not use the key and simply checks if the user authenticated.
