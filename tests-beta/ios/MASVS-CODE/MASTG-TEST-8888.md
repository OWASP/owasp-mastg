---
platform: iOS
title: Not Ensuring Recent OS Version
id: MASTG-TEST-8888
type: [static]
weakness: MASWE-0077
---

## Overview

This test verifies whether your app ensures it is running on a recent version of iOS by checking the value of `MinimumOSVersion` within `Info.plist`. For the purposes of this test the value is checked to see if it is less than 15. However, you should ensure you are using a value that is appropriate for the app being tested and balance between current market share of the iOS version and security.

## Steps

Use `grep` to search the `Info.plist` for `MinimumOSVersion`  (@MASTG-TECH-0058).

## Observation

The output should contain the line of the plist file that defines the `MinimumOSVersion`.

## Evaluation

The test case fails if the `MinimumOSVersion` value is less than 15.
