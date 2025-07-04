---
platform: ios
title: Insertion of Sensitive Data into Logs
id: MASTG-TEST-0x53
type: [dynamic]
weakness: MASWE-0001
prerequisites:
- identify-sensitive-data
---

## Overview

This test is the dynamic counterpart to @MASTG-TEST-0x53-2.

In this test, we will monitor and capture the device logs and then analyze them for sensitive data.

!!! warning Limitation
    - Linking the logs back to specific locations in the app can be difficult and requires manual analysis of the code. As an alternative you can use dynamic analysis with @MASTG-TOOL-0039.
    - Dynamic analysis works best when you interact extensively with the app. But even then there could be corner cases which are difficult or impossible to execute on every device. The results from this test therefore are likely not exhaustive.

## Steps

1. Install the app
2. Start recording the logs
3. Run the app
4. Navigate to the screen of the mobile app you want to analyse the log output from
5. Close the app

## Observation

The output should contain all logged data.

## Evaluation

The test case fails if you can find sensitive data inside the output.

