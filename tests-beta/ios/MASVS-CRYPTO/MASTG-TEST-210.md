---
platform: ios
title: Use of Hardcoded keys
id: MASTG-TEST-0210
type: [static]
weakness: MASWE-0013
---

## Overview

The application appears to use hardcoded encryption key in the code, making it susceptible to multiple vulnerabilities and potential security breaches.

## Steps

1. Run a static analysis tool (semgrep) on the app and look for uses of insecure algorithm.

## Observation

The output should contain a **list of locations where hardcoded key is used in the code**.

## Evaluation

The test case fails if the hardcoded keys is not stored in variable.
