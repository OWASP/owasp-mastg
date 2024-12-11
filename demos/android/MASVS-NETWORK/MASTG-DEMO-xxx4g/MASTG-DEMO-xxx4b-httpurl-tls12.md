---
title: Connection to TLS1.2 Server with SSLSocket.enabledProtocols
platform: android
works: yes
kind: fail
---

## Overview

The following sample code demonstrates how to connect to an **TLS1.2 server** using `HttpsURLConnection` and a custom `SSLSocketFactory` to enforce the use of TLS1.2 by setting the enabled protocols. This approach allows developers to connect to servers with specific TLS versions without modifying the Network Security Configuration (NSC) settings.
