---
platform: android
title: References to Device-Access-Security Policy APIs
id: MASTG-TEST-0242
apis: [Build, KeyguardManager]
type: [static]
weakness: MASWE-0008
best-practices: []
---

## Overview

This test checks whether an application is running on a device with secure policies such as

- device passcode is set
- running on a recent version of Android OS
- running on a secure system build intended for the end users

Testing for USB Debugging and Root detection is now part of MASVS-RESILIENCE.

## Steps

1. Use either @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 to identify all Device-Access-Security Policy APIs.

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if an app doesn't use API that verifies Device-Access-Security Policy.
