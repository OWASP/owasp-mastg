---
title: Connection to TLS1.2 Server with SSLContext.getInstance
platform: android
works: yes
kind: fail
---

## Overview

The following sample code demonstrates how to connect to an **TLS1.2 server** using `HttpsURLConnection` and a custom `SSLContext` to enforce the use of TLS1.2. This approach allows developers to connect to servers with specific TLS versions without modifying the Network Security Configuration (NSC) settings.