---
platform: android
title: Insecure Implementation of Confirm Credentials
id: MASTG-TEST-0x017
type: [static, dynamic]
available_since: 21
deprecated_since: 29
weakness: MASWE-0044
---

## Overview

When an app implements a ["Confirm Credential Flow"](../../../Document/0x05f-Testing-Local-Authentication.md#confirm-credential-flow), if it only verifies whether the key is unlocked without actually using it (e.g., for decrypting local storage or validating data from a remote source), it may be vulnerable to local authentication bypass. Attackers could use dynamic instrumentation tools like @MASTG-TOOL-0001 to intercept and manipulate the logic, falsely simulating successful authentication.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0014).
2. Search for uses of [`setUserAuthenticationRequired`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationRequired(boolean)) or  [`createConfirmDeviceCredentialIntent`](https://developer.android.com/reference/android/app/KeyguardManager#createConfirmDeviceCredentialIntent(java.lang.CharSequence,%20java.lang.CharSequence)) and [`setUserAuthenticationValidityDurationSeconds`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationValidityDurationSeconds(int)).

## Observation

The output should contain the reverse engineered code that uses Confirm Credential.

## Evaluation

The test case fails if the app only checks whether the key is unlocked without performing actual cryptographic operations, such as decrypting or verifying sensitive data.

## Mitigation

Ensure that the app uses the key to decrypt local storage or validate data from a remote source after the user has authenticated.
