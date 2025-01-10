---
title: ProxyDroid
platform: android
source: https://github.com/madeye/proxydroid/
---

ProxyDroid is an app that can help you to set the proxy (e.g. HTTP/HTTPS) on your Android device. It is especially useful for applications that ignore the system's proxy settings, as it uses `iptables` to force the traffic to your proxy. Due to the usage of `iptables`, there are a few important things to take into account:

* ProxyDroid only works on a rooted device
* Only port 80, 443 and 5228 are intercepted
* The proxy needs to be configured in _transparent proxy_ mode
