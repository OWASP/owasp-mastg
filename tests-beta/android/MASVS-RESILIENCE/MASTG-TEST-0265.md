---
platform: android
title: References to StrictMode APIs
id: MASTG-TEST-0265
type: [static]
weakness: MASWE-0094
best-practices: []
profiles: [R]
---

## Overview

This test checks whether the app uses `StrictMode`. While useful for developers to log policy violations such as disk I/O or network operations during development, it can expose sensitive implementation details in the logs that could be exploited by attackers.

## Steps

1. Run a static analysis (@MASTG-TECH-0014) tool to identify all instances of `StrictMode` APIs.

## Observation

The output should identify all instances of `StrictMode` usage in the app.

## Evaluation

The test fails if the app uses `StrictMode` APIs.
