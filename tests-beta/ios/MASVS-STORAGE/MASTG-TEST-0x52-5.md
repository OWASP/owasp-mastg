---
platform: ios
title: References to APIs for Storing Unencrypted Data in Shared Storage
id: MASTG-TEST-0x52-5
type: [static]
profiles: [L1, L2]
best-practices: [MASTG-BEST-0014]
weakness: MASWE-0007
---

## Overview

This test checks whether the app obtains a path to Shared Storage, which may be used to store unencrypted data. It identifies all code locations that could potentially write unencrypted data to Shared Storage.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary.

2. Search for APIs that indicates a use of Shared Storage. This API includes:

    - [`documentDirectory`](https://developer.apple.com/documentation/foundation/filemanager/searchpathdirectory/documentdirectory) for finding the shared directory location

3. Check `Info.plist` file for `UIFileSharingEnabled` and `LSSupportsOpeningDocumentsInPlace` flags

## Observation

The output should contain a list locations from where the app writes data to Shared Storage, and the state of `UIFileSharingEnabled` and `LSSupportsOpeningDocumentsInPlace` flags.

## Evaluation

If you evaluate a framework, the test case fails if you find any use of `documentDirectory` API to obtain a path for storing unencrypted data.

If you evaluate an IPA, the test case fails if both conditions are true:

- find any use of `documentDirectory` API to obtain a path for storing unencrypted data
- `Info.plist` has `UIFileSharingEnabled` and `LSSupportsOpeningDocumentsInPlace` flags enabled
