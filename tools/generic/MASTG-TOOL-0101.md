---
title: disable-flutter-tls-verification
platform: generic
source: https://github.com/NVISOsecurity/disable-flutter-tls-verification
---

[disable-flutter-tls-verification](https://github.com/NVISOsecurity/disable-flutter-tls-verification) is a Frida script that disables Flutter's TLS verification and works on (ARM32, ARM64 and x64) and iOS (ARM64). It uses pattern matching to find [ssl_verify_peer_cert in handshake.cc](https://github.com/google/boringssl/blob/master/ssl/handshake.cc#L323). Further information can be found in [this blog post](https://blog.nviso.eu/2022/08/18/intercept-flutter-traffic-on-ios-and-android-http-https-dio-pinning/).

You can use it via Frida codeshare or by downloading disable-flutter-tls.js from the repo as indicated in these [instructions](https://github.com/NVISOsecurity/disable-flutter-tls-verification).
