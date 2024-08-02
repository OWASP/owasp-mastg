---
platform: android
title: Weak Cryptographic Key Generation 
id: MASTG-TEST-0208
type: [static]
weakness: MASWE-0009
---

## Overview

The application appears to utilize a symmetric algorithm  with a weak key configuration, making it susceptible to multiple vulnerabilities and potential security breaches.

## Steps

1. Run a static analysis tool such as `semgrep` on the code and look for uses of algorithms with insufficient key length.

## Observation

The output should contain a **list of locations where insufficient key lengths are used**.

## Evaluation

The test case fails if you can find the use of algorithms using inappropriate key sizes within the source code. This also fails if deprecated algorithms are used.
