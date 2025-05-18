---
platform: ios
title: Runtime Use of the Keychain Not Requiring User Presence with Frida
id: MASTG-DEMO-0047
code: [swift]
test: MASTG-TEST-0266
kind: fail
---

### Sample

This sample code demonstrates an insecure way of storing a token in the Keychain without requiring user presence. This happens in conjunction with the use of the LocalAuthentication framework to authenticate the user, giving a false sense of security.

{{ MastgTest.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Run `run.sh`.

{{ insecureAuthenticationBiometricsApi.r2 }}

{{ run.sh }}

### Observation

{{ output.asm }}

### Evaluation

The test fails because the output shows references to biometric verification that uses LocalAuthentication API and the Keychain API but does not require user presence. 
