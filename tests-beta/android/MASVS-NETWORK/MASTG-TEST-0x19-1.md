---
title: HTTP URLs
platform: android
id: MASTG-TEST-0x19-1
type: [static]
weakness: MASWE-0050
---

## Overview

An app may have hardcoded HTTP URLs in the app binary, in libs binaries and other places within the APK.

Those URLs are not necessarily used for communication, but can indicate locations where a server is contacted without TLS.

!!! warning Limitations
    If such URLs are actually insecure can depend on other factors. For example if HTTP traffic is disabled in the AndroidManifest, trying to access such URLs will result in an exception, and no insecure connection is made.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Run a static analysis (@MASTG-TECH-0014) tool and look for any `http://` URLs.
3. Verify the found URLs are actually used for communication by inspecting all locations where these URLs are used.

## Observation

The output contains a list of URLs potentially used for communication.

## Evaluation

The test case fails if any HTTP URLs are used for communication.
