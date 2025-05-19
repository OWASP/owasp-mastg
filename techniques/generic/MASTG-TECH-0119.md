---
title: Intercepting HTTP Traffic by Hooking Network APIs at the Application Layer
platform: generic
---

Depending on your goal while testing the app, sometimes it is enough to monitor the traffic before it reaches the network layer or when the responses are received in the app.

This means that you don't need to deploy a fully fledged MITM attack (including ARP Spoofing attacks, etc.) if you simply want to determine if certain sensitive data is being transmitted to the network. With this approach, you will not interfere with any TLS verification or pinning.

You can use [Frida as an alternative](https://gaiaslastlaugh.medium.com/frida-as-an-alternative-to-network-tracing-5173cfbd7a0b)

This technique is also useful for:

- Intercepting traffic in apps that use custom network stacks.
- Intercepting traffic in apps built with specific cross-platform frameworks such as Flutter.
    - Android: @MASTG-TECH-0109
    - iOS: @MASTG-TECH-0110
- Intercepting other types of traffic such as BLE, NFC, etc., where deploying a MITM attack might be very costly and complex.
- Analyzing protocols like MQTT and CoAP, which may require more specialized interception techniques.
- Monitoring WebSocket traffic, which can also necessitate unique interception strategies.

You just have to hook the right functions, e.g., `SSL_write` and `SSL_read` from OpenSSL.

This would work pretty well for apps using standard API library functions and classes; however, there might be some downsides:

- The app might implement a custom network stack and you'll have to spend time analyzing the app to find out the APIs that you can use. See section "Searching for OpenSSL traces with signature analysis" in [this blog post](https://hackmag.com/security/ssl-sniffing/ "Searching for OpenSSL traces with signature analysis").
- It might be very time consuming to craft the right hooking scripts to re-assemble HTTP response pairs (across many method calls and execution threads). You might find [ready-made scripts](https://github.com/fanxs-t/Android-SSL_read-write-Hook/blob/master/frida-hook.py) and even for [alternative network stacks](https://codeshare.frida.re/@owen800q/okhttp3-interceptor/), but depending on the app and the platform, these scripts might need a lot of maintenance and might not _always work_.

See some examples:

- ["Universal interception. How to bypass SSL Pinning and monitor traffic of any application"](https://hackmag.com/security/ssl-sniffing/), sections "Grabbing payload prior to transmission" and "Grabbing payload prior to encryption"
- ["Frida as an Alternative to Network Tracing"](https://gaiaslastlaugh.medium.com/frida-as-an-alternative-to-network-tracing-5173cfbd7a0b)
