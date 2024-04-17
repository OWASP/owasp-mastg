---
platform: ios
title: Weak Cryptographic Key Generation 
tools: [semgrep]
type: [static]
---

## Overview

The iOS app seems to be using a symmetric algorithm called `AES` with a vulnerable configuration, which puts it at risk of various vulnerabilities and potential security breaches.


## Steps

1. Run a static analysis tool (semgrep) on the app and look for uses of insecure algorithm.

## Observation

The output should contain a **list of locations where insecure algorithm are used**.

## Evaluation

The test case fails if you can find the use of AES-128 bit algorithm within the source code.
