---
platform: android
title: Runtime Use of StrictMode APIs
id: MASTG-TEST-0264
type: [dynamic]
weakness: MASWE-0094
best-practices: []
profiles: [R]
---

## Overview

This test checks whether the app uses `StrictMode` by dynamically analyzing the app's behavior and placing relevant hooks to detect the use of `StrictMode` APIs, such as `StrictMode.setVmPolicy` and `StrictMode.VmPolicy.Builder.penaltyLog`.

While `StrictMode` is useful for developers to log policy violations such as disk I/O or network operations during development, it can expose sensitive implementation details in the logs that could be exploited by attackers.

## Steps

1. Use runtime method hooking (see @MASTG-TECH-0043) and look for uses of `StrictMode` APIs.

## Observation

The output should show the runtime usage of `StrictMode` APIs.

## Evaluation

The test fails if the Frida script output shows the runtime usage of `StrictMode` APIs.
