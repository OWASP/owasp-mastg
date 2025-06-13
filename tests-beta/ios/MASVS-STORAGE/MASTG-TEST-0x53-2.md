---
platform: ios
title: Insertion of Sensitive Data into Logs
id: MASTG-TEST-0x53
type: [static]
weakness: MASWE-0001
---

## Overview

On iOS platform, logging APIs like NSLog, NSAssert, NSCAssert, print and printf can inadvertently lead to the leakage of sensitive information. Log messages are recorded in Console and you can access them by `Xcode` or `idevicesyslog`. Although other apps on the device cannot read these logs, direct logging is generally discouraged due to its potential for data leakage

In this test, we will use static analysis to verify whether an app has any logging API which takes sensitive data.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary and look for uses of logging api API.

## Observation

The output should include the location of all logging functions. Check the decompiled code to verify if they receive sensitive data as input.

## Evaluation

The test case fails if you can find the use of APIs such as `NSLog` or `print`. Ideally, a production app shouldn't use any logging functions at all.

### Mitigation

Instead of using APIs such as `NSLog` or `print`, use a macro statement that you can easily disable in the release builds.
