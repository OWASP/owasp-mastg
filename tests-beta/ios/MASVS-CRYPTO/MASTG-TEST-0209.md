---
platform: ios
title: Inappropriate Key Sizes
id: MASTG-TEST-0209
type: [static]
weakness: MASWE-0009
---

## Overview

The application appears to utilize a symmetric algorithm with a weak key configuration, making it susceptible to multiple vulnerabilities and potential security breaches.

## Steps

1. Run a static analysis tool (semgrep) on the app and look for uses of insecure algorithm.

## Observation

The output should contain a **list of locations where insecure algorithm is used**.

## Evaluation

The test case fails if you can find the use of algorithm using appropriate key size within the source code.
