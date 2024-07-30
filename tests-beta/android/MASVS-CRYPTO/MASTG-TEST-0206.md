---
platform: android
title: Weak Cryptographic Key Generation 
tools: [semgrep]
type: [static]
weakness: MASWE-0009
---

## Overview

The application appears to utilize a symmetric algorithm  with a weak key configuration, making it susceptible to multiple vulnerabilities and potential security breaches.

## Steps

1. Run a static analysis tool like semgrep on the code and look for uses of algorithm with insufficient key length.

## Observation

The output should contain a **list of locations where insufficient key lengths are used** .

## Evaluation

The test case fails if you can find the use of algorithm using appropiate key size within the source code. This also fails if less popular algorithms are used.
