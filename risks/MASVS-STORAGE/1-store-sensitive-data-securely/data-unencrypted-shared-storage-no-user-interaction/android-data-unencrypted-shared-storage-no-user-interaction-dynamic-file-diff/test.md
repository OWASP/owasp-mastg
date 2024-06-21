---
platform: android
title: Files Written to External Storage
type: [dynamic]
---

## Overview

The goal of this test is to retrieve the files written to the external storage and inspect them regardless of the APIs used to write them. It uses a simple approach based on [file retrieval from the device storage](../../../../../techniques/android/MASTG-TECH-0002.md) before and after the app is exercised to identify the files created during the app's execution and to check if they contain sensitive data.

## Steps

1. Make sure you have [adb](../../../../../tools/android/MASTG-TOOL-0004.md) installed.
2. [Install the app](../../../../../techniques/android/MASTG-TECH-0005.md).
3. Before running the app, [get the current list of files](../../../../../techniques/android/MASTG-TECH-0002.md) in the external storage.
4. Exercise the app.
5. After running the app, retrieve the list of files in the external storage again.
6. Calculate the difference between the two lists.

## Observation

The **output** contains a list of files that were created during the excersising the app.

## Evaluation

The test case fails if the files found above are not encrypted and leak sensitive data.

To confirm this, you can [reverse engineer the app](../../../../../techniques/android/MASTG-TECH-0017.md) and [inspect the code](../../../../../techniques/android/MASTG-TECH-0023.md).
