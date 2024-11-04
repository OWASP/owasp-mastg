---
title: SSLSockets without Hostname Verification
platform: android
id: MASTG-TEST-0x19-2
type: [static]
weakness: MASWE-0050
---

## Overview

`SSLSocket` does not perform hostname verification (see ["Android documentation"](https://developer.android.com/privacy-and-security/security-ssl#WarningsSslSocket)). This needs to be implemented securely by the app itself.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Run a static analysis (@MASTG-TECH-0014) tool and look for all usages of `SSLSocket`.
3. Verify each usage performans manual hostname verification correctly.

## Observation

The output contains a list locations where `SSLSocket` is used and if hostname verification is done correctly for each.

## Evaluation

The test case fails if any hostname verification is missing, or implemented insecurely.
