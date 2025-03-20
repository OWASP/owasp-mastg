---
title: ProxyDroid
platform: android
source: https://github.com/madeye/proxydroid/
---

ProxyDroid is an open source app [available in Google Play](https://play.google.com/store/apps/details?id=org.proxydroid) that configures your device to send HTTP(S) traffic to a proxy. It is especially useful for apps that ignore the system's proxy settings, as it uses `iptables` to force the traffic to your proxy.

Due to the usage of `iptables`, there are a few limitations to consider:

- ProxyDroid only works on rooted devices
- Only port 80, 443 and 5228 are intercepted
- The proxy needs to be configured in _transparent proxy_ mode
