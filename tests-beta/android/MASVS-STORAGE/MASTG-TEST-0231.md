---
platform: android
title: References to Logging APIs
id: MASTG-TEST-0231
apis: [Log, Logger, System.out.print, System.err.print, java.lang.Throwable#printStackTrace, android.util.Log]
type: [static]
weakness: MASWE-0001
best-practices: [MASTG-BEST-0002]
profiles: [L1, L2, P]
---

## Overview

This test verifies if an app uses [logging APIs](../../../0x05d-Testing-Data-Storage.md/#logs) like `android.util.Log`, `Log`, `Logger`, `System.out.print`, `System.err.print`, and `java.lang.Throwable#printStackTrace`.

## Steps

1. Use either @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 to identify all logging APIs.

## Observation

The output should contain a list of locations where logging APIs are used.

## Evaluation

The test fails if an app logs sensitive information from any of the listed locations.
