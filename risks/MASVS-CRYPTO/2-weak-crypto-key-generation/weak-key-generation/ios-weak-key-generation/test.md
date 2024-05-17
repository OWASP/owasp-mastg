---
platform: ios
title: Weak Cryptographic Key Generation 
tools: [semgrep]
type: [static]
---

## Overview

The application appears to utilize a symmetric algorithm known as `AES-128` with a weak key configuration, making it susceptible to multiple vulnerabilities and potential security breaches.

## Steps

1. Run a static analysis tool (semgrep) on the app and look for uses of insecure algorithm.

## Observation

The output should contain a **list of locations where insecure algorithm is used**.

## Evaluation

The test case fails if you can find the use of less secure algorithm is detected within the source code.
