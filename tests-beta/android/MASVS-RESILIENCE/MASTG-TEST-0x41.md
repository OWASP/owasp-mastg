---
platform: android
title: Testing if StrictMode is enabled
id: MASTG-TEST-0X41
apis: [StrictMode]
type: [dynamic]
weakness: MASWE-0094
---

## Overview

This test verifies if an app enables [StrictMode](../../../0x05i-Testing-Code-Quality-and-Build-Settings/#strictmode) in production.

## Steps

1. Install the production build of your app on your device or emulator.
2. Uses @MASTG-TECH-0009 to show the system logs `StrictMode` creates.
3. Open the app and let it execute.
## Observation

The output should contain a list of log statements related to `StrictMode`.

## Evaluation

The test fails if an app logs any `StrictMode` policy violations.
