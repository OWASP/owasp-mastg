---
title: frida-multiple-unpinning
platform: android
source: https://codeshare.frida.re/@akabe1/frida-multiple-unpinning
---

A Frida CodeShare script to bypass various forms of TLS pinning. This is one of the most extensive TLS pinning bypass scripts available on CodeShare. One of its main strengths is a dynamic bypass which detects instantiations of the `SSLPeerUnverifiedException` class and automatically patches the method responsible for throwing the exception.

You can run the script directly with Frida:

```bash
$ frida -U --codeshare akabe1/frida-multiple-unpinning -f YOUR_BINARY
```
