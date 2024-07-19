---
platform: android
title: Data Stored in the App Sandbox at Runtime
id: MASTG-TEST-0207
type: [dynamic, filesystem]
mitigations:
- android-use-keystore
- android-use-androidx-security
prerequisites:
- identify-sensitive-data
weakness: MASWE-0006
---

## Overview

The goal of this test is to retrieve the files written to the **internal storage** and inspect them regardless of the APIs used to write them. It uses a simple approach based on [file retrieval from the device storage](/MASTG/techniques/android/MASTG-TECH-0002) before and after the app is exercised to identify the files created during the app's execution and to check if they contain sensitive data.

## Steps

1. Start the device.

2. Take a first [copy of the app's private data directory](/MASTG/techniques/android/MASTG-TECH-0008.md) to have as a reference for offline analysis.

3. Launch and use the app going through the various workflows while inputting sensitive data wherever you can. Taking note of the data you input can help identify it later using tools to search for it.

4. Take a second copy of the app's private data directory for offline analysis and make a diff using the first copy to identify all files created or modify during your testing session.

## Observation

The output should contain a list of files that were created in the app's private storage during  execution.

## Evaluation

Attempt to identify and decode data that has been encoded using methods such as base64 encoding, hexadecimal representation, URL encoding, escape sequences, wide characters and common data obfuscation methods such as xoring. Also consider identifying and decompressing compressed files such as tar or zip. These methods obscure but do not protect sensitive data.

Search the extracted data for items such as keys, passwords and any sensitive data inputted into the app. The test case fails if you find any of this sensitive data.
