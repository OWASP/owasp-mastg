---
Title: Testing Enforced Updating
ID: MASTG-TEST-0x80
Link: https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0080/
Platform: ios
MASVS v1: ['MSTG-ARCH-9']
MASVS v2: ['MASVS-CODE-2']
type: [dynamic]
---

## Overview

When a vulnerability is found in the app, it should be possible to force the user to update the application to continue using it.

## Steps

1. Obtain a MitM position between the application and its backend (see @MASTG-TECH-0063).
2. Identify if version information is sent to the backend. This can be as part of a header, the URL, a URL parameter or the HTTP body.
3. Interact with the backend to see if different version numbers trigger different responses.
4. If a different response can be identified, modify an active request with the old version number to examine how the application reacts to the new backend response.

## Observation

The server responds differently to older versions.

## Evaluation

The test case fails if the application does not send its version information to the backend.
