---
platform: ios
title: Insertion of Sensitive Data into Logs
id: MASTG-TEST-0x53
type: [dynamic]
weakness: MASWE-0001
---

## Overview

On iOS platform, logging APIs like NSLog, NSAssert, NSCAssert, print and printf can inadvertently lead to the leakage of sensitive information. Log messages are recorded in Console and you can access them by `Xcode` or `idevicesyslog`. Although other apps on the device cannot read these logs, direct logging is generally discouraged due to its potential for data leakage.

In this test, we will use dynamic analysis to verify what data is logged to the Console.

## Steps

1. Install the app
2. Start recording the logs
3. Run the app
4. Navigate to the screen of the mobile app you want to analyse the log output from
5. Close the app

## Observation

The output should contain all logged data.

## Evaluation

The test case fails if you can find sensitive data inside the output. Ideally, a production app shouldn’t use any logging functions at all.

### Mitigation

Instead of using APIs such as `NSLog` or `print`, use a macro statement that you can easily disable in the release builds.
