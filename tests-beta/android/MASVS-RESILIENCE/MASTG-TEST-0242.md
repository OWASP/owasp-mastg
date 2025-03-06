---
platform: android
title: References to APIs that reveal if a device secure lock is in place
id: MASTG-TEST-0242
apis: [KeyguardManager]
type: [static]
weakness: MASWE-0008
best-practices: []
---

## Overview

This test verifies whether an application is running on a device with a passcode set.

## Steps

1. Use @MASTG-TOOL-0110 to identify the API that checks whether a device has a passcode set

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if an app doesn't use any API to verify passcode presence.
