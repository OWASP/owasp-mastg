---
platform: android
title: Logging of StrictMode Violations
id: MASTG-TEST-0263
apis: [StrictMode]
type: [dynamic]
weakness: MASWE-0094
profiles: [R]
---

## Overview

This test checks whether an app enables [`StrictMode`](../../../Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#strictmode) in production. While useful for developers to log policy violations such as disk I/O or network operations in production apps, leaving `StrictMode` enabled can expose sensitive implementation details in the logs that could be exploited by attackers.

## Steps

1. Install the production build of your app on your device or emulator.
2. Uses @MASTG-TECH-0009 to show the system logs `StrictMode` creates.
3. Open the app and let it execute.

## Observation

The output should contain a list of log statements related to `StrictMode`.

## Evaluation

The test fails if an app logs any `StrictMode` policy violations.
