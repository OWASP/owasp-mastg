---
title: HTTP URLs
platform: android
id: MASTG-TEST-0233
type: [static]
weakness: MASWE-0050
---

## Overview

An Android app may have hardcoded HTTP URLs embedded in the app binary, library binaries, or other resources within the APK. These URLs may indicate potential locations where the app communicates with servers over an unencrypted connection.

!!! warning Limitations
    The presence of HTTP URLs alone does not necessarily mean they are actively used for communication. Their usage may depend on runtime conditions, such as how the URLs are invoked and whether cleartext traffic is allowed in the app's configuration. For example, HTTP requests may fail if cleartext traffic is disabled in the AndroidManifest.xml or restricted by the Network Security Configuration.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Run a static analysis (@MASTG-TECH-0014) tool and look for any `http://` URLs.

## Observation

The output contains a list of URLs and their locations within the app.

## Evaluation

The test case fails if any HTTP URLs are confirmed to be used for communication.

Since the mere presence of hardcoded HTTP URLs does not guarantee their use, you need to validate their actual usage. Inspect the reported code locations in the app and analyze how the HTTP URLs are referenced. For example, are they simply stored as constants or used to create HTTP requests with networking APIs like `HttpURLConnection` or `OkHttp`?
