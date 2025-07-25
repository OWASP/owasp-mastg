---
title: Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding
platform: android
id: MASTG-TEST-0289
type: [static]
profiles: [L2]
best-practices: [MASTG-BEST-0014]
weakness: MASWE-0055
---

## Overview

This test verifies that the app hides sensitive content from the screen when it moves to the background. This is important because when an app enters the background, the system captures a screenshot of its current view, which might be accessed by attackers.

## Steps

1. Exercise your app until you get to a screen with confidential data
2. Move the app to the background.
3. Use a tool such as @MASTG-TOOL-0002 to copy the screenshot taken by the system to your laptop for further analysis. The system stores the screenshots at their containers `/data/system_ce/0/snapshots` or `/data/system`.
4. Verify that the screenshots don't display any confidential data

## Observation

The output should include a list of screenshots cached when app entered the background state.

## Evaluation

The test case fails if you find sensitive data on the screenshot.
