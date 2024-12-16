---
platform: ios
title: Testing Whether the App is Debuggable
id: MASTG-TEST-0x82
type: [static, dynamic]
weakness: MASWE-0101
---

## Overview

The test evaluates whether an iOS application is configured to allow debugging. If an app is debuggable, attackers can leverage debugging tools to reverse-engineer the application, analyse its runtime behaviour, and potentially compromise sensitive data or functionality.

## Steps

1. Run a static analysis using @MASTG-TOOL-0111 to extract entitlements from the binary to check the value of the `get-task-allow` key and is set to `true`.
2. Run a [dynamic analysis](../../../techniques/ios/MASTG-TECH-0084.md) using @MASTG-TOOL-0057.

## Observation

The entitlement get-task-allow is false, and anti-reverse engineering measures prevent debugger attachment attempts.

## Evaluation

The test fails as the entitlement get-task-allow is true, allowing debugger attachment.
