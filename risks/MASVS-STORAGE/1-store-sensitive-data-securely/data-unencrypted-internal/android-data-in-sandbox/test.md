---
platform: android
title: Sensitive Data Written to Private Data Directory (Sandbox) Unencrypted.
type: [dynamic, filesystem]
mitigations:
- android-use-keystore
- android-use-androidx-security
prerequisites:
- identify-sensitive-data
---

## Steps

1. Start the device.

2. Launch and use the app going through the various workflows while inputting sensitive data wherever you can. Taking note of the data you input can help identify it later using tools to search for it.

3. Take a copy of the app's private data directory for offline analysis. Using tar will preserve the filesystem structure and permissions.

4. Search the extracted data for items such as keys, passwords and any sensitive data inputted into the app.

5. Check files for sensitive data that has been encoded with algorithms such as base64 which obscures but does not protect sensitive data.

## Observation

Files within the private data directory contain sensitive data.

## Evaluation

The test case fails if you find sensitive data in the app's private data directory which has not been encrypted with strong cryptography. This includes plaintext data as well as encoding such as base64 or obfuscation such as xoring.
