---
title: Connection to HTTP Server with HttpsURLConnection and Network Security Config Per-Domain Exception
platform: android
works: yes
kind: fail
---

## Overview

The following sample code demonstrates how to connect to an **HTTP server** using `HttpURLConnection` and adding an exception in the network security configuration file to disable certificate validation for the specified domain.

If the domain-config is present but set like `cleartextTrafficPermitted="false"` or if the network security configuration file is not configured in the AndroidManifest or is missing, the connection will fail with an exception like:

```plaintext
java.io.IOException: Cleartext HTTP traffic to http.badssl.com not permitted
```

Otherwise, the connection will succeed and the HTML content of the specified URL will be displayed.
