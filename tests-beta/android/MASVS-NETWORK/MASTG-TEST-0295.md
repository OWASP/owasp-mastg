---
title: Insecure or Missing Security Provider Update (Static)
platform: android
id: MASTG-TEST-0295
type: [static]
weakness: MASWE-0052
profiles: [L2]
best-practices: [MASTG-BEST-0014]
---

## Overview

This test checks whether the Android app ensures the Security Provider (@MASTG-KNOW-0011) is [updated to mitigate SSL/TLS vulnerabilities](https://developer.android.com/privacy-and-security/security-gms-provider). The provider should be updated using Google Play Services APIs, and the implementation should handle exceptions securely.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Use static analysis (@MASTG-TECH-0014) to search for usage of `ProviderInstaller.installIfNeeded` or `ProviderInstaller.installIfNeededAsync`.

## Observation

The output should list all locations where the Security Provider update is performed and how exceptions are handled.

## Evaluation

The test fails if the app does not update the provider, or exception handling is missing/insecure. Check that these calls occur early in the app lifecycle (e.g., in `Application` or main `Activity`).

The test passes if the app updates the Security Provider using the correct API and handles exceptions securely.
