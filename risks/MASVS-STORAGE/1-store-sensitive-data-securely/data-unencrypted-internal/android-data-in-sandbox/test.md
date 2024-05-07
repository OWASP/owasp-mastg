---
platform: android
title: Sensitive Data Written to Private Data Directory (Sandbox) Unencrypted
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

3. Take a copy of the app's private data directory for offline analysis. See: https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0008.

4. Attempt to identify and decode data that has been encoded using methods such as base64 encoding, hexadecimal representation, URL encoding, escape sequences, wide characters and common data obfuscation methods such as xoring. Also consider identifying and decompressing compressed files such as tar or zip. These methods obscure but do not protect sensitive data.

## Observation

Data extracted from the app's private data directory which has been decompressed, decoded or deobfuscated where required.

## Evaluation

Search the extracted data for items such as keys, passwords and any sensitive data inputted into the app. The test case fails if you find any of this sensitive data.
