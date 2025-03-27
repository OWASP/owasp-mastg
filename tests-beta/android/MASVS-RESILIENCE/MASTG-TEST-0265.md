---
platform: android
title: References to StrictMode APIs
id: MASTG-TEST-0265
type: [static]
weakness: MASWE-0094
best-practices: []
---

## Overview

This test checks whether the app uses `StrictMode`, which while useful for developers to log policy violations such as disk I/O or network operations in production apps, can expose sensitive implementation details in the logs that could be exploited by attackers.

## Steps

1. Use @MASTG-TOOL-0110 to identify all instances of `StrictMode`
   APIs.

## Observation

The output should identify all instances of `StrictMode` usage in the app.

## Evaluation

The test fails if the app uses `StrictMode` APIs.