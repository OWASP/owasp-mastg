---
platform: ios
title: References to APIs for Storing Unencrypted Data in Private Storage
id: MASTG-TEST-0x52-2
type: [static]
profiles: [L2]
best-practices: [MASTG-BEST-0014]
weakness: MASWE-0006
---

## Overview

This test checks whether the app obtains a path to Private Storage, which may be used to store unencrypted data. It identifies all code locations that could potentially write unencrypted data to Private Storage.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary.

2. Search for APIs that indicates a use of Private Storage. This API includes:

    - [`UserDefaults`](https://developer.apple.com/documentation/foundation/userdefaults)
    - [`documentDirectory`](https://developer.apple.com/documentation/foundation/filemanager/searchpathdirectory/documentdirectory)
    - [`applicationSupportDirectory`](https://developer.apple.com/documentation/foundation/filemanager/searchpathdirectory/applicationsupportdirectory)
    - [`userDomainMask`](https://developer.apple.com/documentation/foundation/filemanager/searchpathdomainmask/1408037-userdomainmask)

## Observation

The output should contain a list locations from where the app writes data to Private Storage

## Evaluation

The test case fails if you find any use of these APIs on unencrypted sensitive data.
