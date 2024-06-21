---
platform: android
title: Files Written to External Storage
type: [dynamic]
---

## Overview

The goal of this test is to simply retrieve the files and inspect them regardless of the APIs used to write them. Therefore, we'll use a simple approach that consists of getting the list of all files in the shared and external storage before and after the app is exercised, and then comparing them, as this may reveal sensitive files that were unintentionally stored.

## Steps

1. Make sure you have ADB installed.

2. Install the app.

3. Execute `run_before.sh` before opening the app to mark the timestamp.

4. Exercise the app.

5. Execute `run_after.sh` to list all the files created by the app in the external storage.

## Observation

The **output** contains a list of files that were created during the excersising the app.

## Evaluation

The test case fails if the files found above are not encrypted and leak sensitive data.
