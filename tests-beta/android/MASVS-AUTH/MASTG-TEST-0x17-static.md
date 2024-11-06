---
platform: android
title: Insecure Local Authentication
id: MASTG-TEST-0x017-static
type: [static]
available_since: 21
weakness: MASWE-0044
---

## Overview

Applications can implement local authentication in various ways, as explained in ["Android Local Authentication"](../../../Document/0x05f-Testing-Local-Authentication.md#Android%20Local%20Authentication). To make sure the application uses local authentication correctly, you need to verify if the application uses result-based authentication.

If the application uses event-based authentication instead of result-based authentication, the authentication flow can be bypassed by tools such as @MASTG-TOOL-0001 or @MASTG-TOOL-0029.

## Steps

1. Identify keys created in the KeyStore which are protected by `setUserAuthenticationRequired`
2. Identify how the key is used after the user has succesfully provided their biometrics or device credential. The exact method depends on the used API, but can include:
   1. BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded
   2. FingerprintManager.AuthenticationCallback.onAuthenticationSucceeded

## Observation

The application may use the unlocked key to decrypt sensitive information, or it may simply continue with the flow and not use the key in any meaningful way. Note that only checking for the occurence of `setUserAuthenticationRequired` is not enough, as some applications will protect a key with user authentication in order to trigger the local authentication prompt, but not actually use it once it is unlocked.

## Evaluation

The test case fails if the unlocked key is not used to unlock the protected data.

## Mitigation

Ensure that the app uses the unlocked key to decrypt local storage after the user has authenticated.
