---
platform: android
title: References to Platform Version APIs
id: MASTG-TEST-0242
apis: [Build]
type: [static]
weakness: MASWE-0077
best-practices: []
---

## Overview

This test checks whether an application is running on a recent version of an operating system.

## Steps

1. Use either @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 to identify APIs that check the version of the operating system.

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if an app doesn't use API that verifies operating system version.
