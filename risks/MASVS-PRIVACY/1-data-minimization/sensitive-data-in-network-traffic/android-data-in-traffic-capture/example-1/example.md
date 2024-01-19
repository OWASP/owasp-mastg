---
platform: android
title: Detecting Sensitive Data in Network Traffic
tools: [mitmproxy]
code: [kotlin]
---

### Sample

{{ send-post-request.kt }}

### Steps

Let's run our mitmproxy with our custom script for logging sensitive data and dump the relevant traffic to a file.

{{ ../mitm_sensitive_logger.py }}

{{ run.sh }}

### Observation

The script has identified several instances in the network traffic where sensitive data is sent.

{{ sensitive_data.log }}

### Evaluation

Review each of the reported instances.

- The first instance is a POST request to `https://httpbin.org/post` which contains the sensitive data values in the request body.
- The second instance is a response from `https://httpbin.org/post` which contains the sensitive data values in the response body.

This is a dummy example, but in a real-world scenario, you should determine which of the reported instances are privacy-relevant and need to be addressed. You can use the list of sensitive data you identified in the [Identify your sensitive data](MASTG-KNOW-0001) section as a reference.

Note that both the request and the response are encrypted using TLS, so they can be considered secure. However, this might represent a privacy issue depending on the relevant privacy regulations and the app's privacy policy. You should now check the privacy policy and the App Store Privacy declarations to see if the app is allowed to send this data to a third-party.
