---
Title: Testing Enforced Updating
ID: MASTG-TEST-0x80
Link: https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0080/
Platform: ios
MASVS v1: ['MSTG-ARCH-9']
MASVS v2: ['MASVS-CODE-2']
type: [static]
---

## Overview

When a vulnerability is found in the app, it should be possible to force the user to update the application to continue using it.

## Steps

1. Examine the startup flow of the application. Identify if the application calls out to a backend with the application's version information included.
2. Examine if the application can handle a specific response from the backend indicating that the application must be updated. For example, the application might evaluate the response from the backend and show a specific error message. Note that the error message can also come from the backend, so the lack of a custom error message in the application does not mean that the feature isn't implemented.

## Observation

The application contains specific logic to handle a force-update event. The user may be able to ignore the prompt and continue using the application, or they may be unable to use the application without updating.

## Evaluation

The test case fails if the application does not contain any logic to handle a forced application update. Additionally, the test case fails if the application informs the user that they must update, but the user can ignore the prompt and still use the application.
