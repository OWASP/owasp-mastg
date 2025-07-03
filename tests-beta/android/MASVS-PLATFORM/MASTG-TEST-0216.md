---
title: References to Screen Capturing Prevention APIs
platform: android
id: MASTG-TEST-0216
type: [static]
best-practices: [MASTG-BEST-0014]
weakness: MASWE-0055
---

## Overview

This test verifies whether an app uses APIs to prevent or detect screen capturing. While prevention is preferable to detection, this test ensures that the app is aware of potential screenshot issues. On Android, several APIs allow developers to detect when screenshots are taken, such as:

- [`FLAG_SECURE`](https://developer.android.com/security/fraud-prevention/activities#flag_secure): prevents screen recording.
- [`DETECT_SCREEN_CAPTURE`](https://developer.android.com/about/versions/14/features/screenshot-detection#implementation): detects when a screenshot is taken.

## Steps

1. Run a static analysis tool, such as @MASTG-TOOL-0110, on the code to identify instances of relevant API usage.

## Observation

The output should include a list of locations where the relevant APIs are used.

## Evaluation

The test case fails if you cannot find the relevant APIs on the Activities that display sensitive data.
