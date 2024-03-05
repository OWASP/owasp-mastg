---
platform: android
title: Declaration of the external storage permission
apis: []
type: [static]
---

## Overview

An app must declare an intent to write to external storage in order to save files in the public locations.

## Steps

1. Run a [static analysis](../../../../../techniques/android/MASTG-TECH-0014.md) tool on the app and look for a use of sensitive permissions.


## Observation

The output shows that the manifest files declares `WRITE_EXTERNAL_STORAGE` permission at line 5.

## Evaluation

Inspect app's source code to make sure the data stored externally is secure.
