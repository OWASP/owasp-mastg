---
platform: ios
title: Runtime Data Storage in the App Sandbox
id: MASTG-TEST-0x52-1
type: [dynamic]
profiles: [L2]
weakness: MASWE-0006
best-practices: [MASTG-BEST-0014]
---

## Overview

This test retrieves files written to **Private Storage** regardless of the APIs used to write them. It uses a simple approach based on file retrieval from the device storage (@MASTG-TECH-0052) before and after the app is exercised to identify the files created during the app's execution and to check if they contain sensitive data.

## Steps

1. Start the device.

2. Copy the content of app's private data directory (@MASTG-TECH-0052) to have as a reference for later analysis.

3. Interact with the app to initiate filesystem writes.

4. Take a second copy of the app's private data directory and diff it with the first copy to identify all files created or modified during your testing session.

## Observation

The output should contain a list of files that were created in the app's private storage during execution.

## Evaluation

The test case fails if you find any of this sensitive data.

Attempt to identify and decode data that has been encoded using methods such as base64 encoding, hexadecimal representation, URL encoding, escape sequences, wide characters and common data obfuscation methods such as xoring. Also consider identifying and decompressing compressed files such as tar or zip. These methods obscure but do not protect sensitive data.
