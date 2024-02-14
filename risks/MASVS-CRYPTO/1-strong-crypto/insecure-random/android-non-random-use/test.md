---
platform: android
title: Non-random Sources Usage
type: [static]
mitigations:
- android-use-secure-random
prerequisites:
- identify-sensitive-data
- identify-security-relevant-contexts
---

## Overview

Android applications sometimes use non-random sources to generate "random" values, leading to potential security vulnerabilities. Common practices include relying on the current time, such as `Date().getTime()`, or accessing `Calendar.MILLISECOND` to produce values that are easily guessable and reproducible.

## Steps

1. Run a [static analysis](../../../../../techniques/android/MASTG-TECH-0014.md) tool on the app and look for uses of non-random sources.

## Observation

The output should contain a **list of locations where non-random sources are used**.

## Evaluation

Inspect the app source code using the provided location information.

The test case fails if you can find security-relevant values, such as passwords or tokens, generated using non-random sources.
