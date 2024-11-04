---
title: HTTP URLs
platform: android
id: MASTG-TEST-0x19-1
type: [static]
weakness: MASWE-0050
---

## Overview

The app should not contain any HTTP URLs which might be used for communicating with a server.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Run a static analysis (@MASTG-TECH-0014) tool and look for any `http://` URLs.
3. Verify the found URLs are actually used for communication.

## Observation

The output contains a list of URLs which are used for communication.

## Evaluation

The test case fails if any HTTP URLs are used for communication.
