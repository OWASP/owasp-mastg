---
title: Connection to HTTP Server with HttpsURLConnection and usesCleartextTraffic in AndroidManifest but an empty Network Security Config
platform: android
works: yes
kind: pass
---

## Overview

The following sample code demonstrates how to connect to an **HTTP server** using `HttpURLConnection` and adding `android:usesCleartextTraffic="true"` to the AndroidManifest to enable cleartext traffic for all domains. However, the app does contain an empty Network Security Configuration (NSC) file, which just because of its presence, disables cleartext traffic for all domains.

```plaintext
java.io.IOException: Cleartext HTTP traffic to http.badssl.com not permitted
```
