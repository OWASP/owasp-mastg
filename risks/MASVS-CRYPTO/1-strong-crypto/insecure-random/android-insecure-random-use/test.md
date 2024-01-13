---
platform: android
title: Insecure Random API Usage
type: [static]
mitigations:
- android-use-secure-random
prerequisites:
- identify-sensitive-data
- identify-security-relevant-contexts
---

## Steps

1. Run a [static analysis](../../../../../techniques/android/MASTG-TECH-0014.md) tool on the app and look for insecure random APIs.

## Observation

The output should contain a **list of locations where insecure random APIs are used**.

## Evaluation

Inspect the app source code using the provided location information.

The test case fails if you can find random numbers generated using those APIs that are used in security-relevant contexts.
