---
title: Debuggable Flag Not Disabled in the AndroidManifest
platform: android
id: MASTG-TEST-0x39-1
type: [static]
weakness: MASWE-0067
---

## Overview

This test case checks if the application has the debuggable flag set in the AndroidManifest.xml. If this flag is set, an attacker can attach a debugger, and e.g., read and modify internals of the application.

!!! note Other ways to debug the application
    Not enabling debugging in the AndroidManifest.xml does fully prevent all possibilities to debug the app. See @MASWE-0101 for more details on how to prevent debugging.

## Steps

1. View the AndroidManifest.xml, e.g., via @MASTG-TOOL-0121.
2. If the output of @MASTG-TOOL-0121 contains `application-debuggable`, the app has the debuggable flag set.

## Observation

The output should contain the contents of the AndroidManifest.xml.

## Evaluation

The test case fails if the debuggable flag is set.
