---
platform: android
title: Usage of API to get to external storage locations
apis: [Environment#getExternalStoragePublicDirectory, Environment#getExternalStorageDirectory, Environment#getExternalFilesDir, Environment#getExternalCacheDir]
type: [static]
---

## Overview

Developers can obtain paths to the external storage locations with `Environment.getExternal...` methods. This test searches for a set of APIs that are commonly used for obtaining external storage locations in source code.

## Steps

1. Run a [static analysis](../../../../../techniques/android/MASTG-TECH-0014.md) tool on the app and look for uses of `getExternal...` API.


## Observation

The output should contain a **list of locations where paths to external storage are returned**.

## Evaluation

Inspect app's source code using the provided location information.

The test case fails if you find code that writes sensitive unencrypted to these locations.
