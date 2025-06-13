---
platform: ios
title: Debuggable Entitlement Enabled in the entitlements.plist
id: MASTG-TEST-0261
type: [static]
weakness: MASWE-0067
profiles: [R]
---

## Overview

The test evaluates whether an iOS application is configured to allow debugging. If an app is debuggable, attackers can leverage debugging tools (see @MASTG-TECH-0084) to analyse the runtime behaviour of the app, and potentially compromise sensitive data or functionality.

## Steps

1. Use @MASTG-TECH-0111 to extract entitlements from the binary.
2. Search for the `get-task-allow` key.

## Observation

The output contains the value of the `get-task-allow` entitlement.

## Evaluation

The test fails if the `get-task-allow` entitlement is `true`.
