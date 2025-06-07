---
title: Hardcoded HTTP URLs
platform: android
id: MASTG-TEST-0233
type: [static]
weakness: MASWE-0050
related-tests: [MASTG-TEST-0235, MASTG-TEST-0236, MASTG-TEST-0238]
profiles: [L1, L2]
---

## Overview

An Android app may have hardcoded HTTP URLs embedded in the app binary, library binaries, or other resources within the APK. These URLs may indicate potential locations where the app communicates with servers over an unencrypted connection.

!!! warning Limitations
    The presence of HTTP URLs alone does not necessarily mean they are actively used for communication. Their usage may depend on runtime conditions, such as how the URLs are invoked and whether cleartext traffic is allowed in the app's configuration. For example, HTTP requests may fail if cleartext traffic is disabled in the AndroidManifest.xml or restricted by the Network Security Configuration. See @MASTG-TEST-0235.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Run a static analysis (@MASTG-TECH-0014) tool and look for any `http://` URLs.

## Observation

The output contains a list of URLs and their locations within the app.

## Evaluation

The test case fails if any HTTP URLs are confirmed to be used for communication.

The presence of hardcoded HTTP URLs does not inherently mean they are used; their actual usage must be validated through careful inspection and testing:

- **Reverse Engineering**: Inspect the code locations where the HTTP URLs are referenced. Determine if they are merely stored as constants or actively used to create HTTP requests through networking APIs like `HttpURLConnection` or `OkHttp`.
- **Static Analysis**: Analyze the app's configuration to identify whether cleartext traffic is permitted. For example, check the AndroidManifest.xml for `android:usesCleartextTraffic="true"` or inspect the `network_security_config`. Refer to @MASTG-TEST-0235 for detailed guidance.

Additionally, complement this static inspection with dynamic testing methods:

- **Dynamic Analysis**: Use tools like Frida to hook into networking APIs at runtime. This can reveal how and when the HTTP URLs are used during execution. See @MASTG-TEST-0238 for more details.

- **Network Traffic Interception**: Capture and analyze network traffic using tools like Burp Suite, mitmproxy, or Wireshark. This approach confirms whether the app connects to the identified HTTP URLs during real-world usage but depends on the tester's ability to exercise the app's functionality comprehensively. See @MASTG-TEST-0236.
