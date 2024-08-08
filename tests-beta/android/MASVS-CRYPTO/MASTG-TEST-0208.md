---
platform: android
title: Inappropriate Key Sizes 
id: MASTG-TEST-0208
type: [static]
weakness: MASWE-0009
---

## Overview

The application appears to utilize a symmetric algorithm  with a weak key configuration, making it susceptible to multiple vulnerabilities and potential security breaches.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0110 on the code and look for uses of algorithms with insufficient key length.

## Observation

The output should contain a **list of locations where insufficient key lengths are used**.

## Evaluation

The test case fails if you can find the use of inappropriate key sizes within the source code.
