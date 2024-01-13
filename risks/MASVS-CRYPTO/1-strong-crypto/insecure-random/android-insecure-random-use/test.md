---
platform: android
title: Insecure Random API Usage
type: [static]
mitigations:
- android-use-secure-random
prerequisites:
- MASTG-KNOW-0001
- MASTG-KNOW-0002
---

## Prerequisites

- [Identify your sensitive data](MASTG-KNOW-0001)
- [Identify your security-relevant contexts](MASTG-KNOW-0002)

## Steps

1. Run a [static analysis](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/) tool on the app and look for insecure random APIs.

## Observation

The **static analysis output** contains a list of locations where insecure random APIs are used in the app.

## Evaluation

Inspect the code of the app looking for the APIs identified by the static analysis tool.

The test case fails if you can find random numbers generated using those APIs that are used in security-relevant contexts.
