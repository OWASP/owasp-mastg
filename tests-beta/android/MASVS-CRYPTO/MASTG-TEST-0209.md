---
platform: android
title: hardcoded-crypto-keys-usage
tools: [semgrep]
type: [static]
---

## Overview

The application appears to utilize a harcoded key for its cryptographic implementations.

## Steps

1. Run a static analysis tool like semgrep on the code and look for uses of hardcoded keys getting used.

## Observation

The output should contain a **list of locations where hardcoded keys are getting used** .

## Evaluation

The test case fails if you can find the hardcoded key is just stored and not used.
