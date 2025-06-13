---
title: Correct implementation of server certificate verification
platform: android
id: MASTG-TEST-0234-1
type: [static]
weakness: MASWE-0052
---

## Overview

When `checkServerTrusted` is used without proper error handling indicate that server certificates are not being properly validated which allow for the possibility of MITM attacks.

## Steps

1. Reverse engineer (@MASTG-TECH-0017) the app (@MASTG-APP-0018).
2. Run a static analysis (@MASTG-TECH-0014) tool for the app (@MASTG-APP-0018) and look for all usages of `checkServerTrusted`.

## Observation

The output contains a list of locations where `checkServerTrusted` is used.

## Evaluation
