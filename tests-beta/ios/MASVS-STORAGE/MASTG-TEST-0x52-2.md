---
platform: ios
title: References to APIs for Accessing Private Storage
id: MASTG-TEST-0x52-2
type: [static]
profiles: [L1]
best-practices: [MASTG-BEST-0014]
weakness: MASWE-0006
---

## Overview

This test is a static counterpart to @MASTG-TEST-0x52-3.

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
