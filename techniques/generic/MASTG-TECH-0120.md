---
title: Intercepting HTTP Traffic Using an Interception Proxy
platform: generic
---

Interception proxies are the most common method for intercepting mobile app traffic. They work by setting up a proxy server that intercepts and logs all HTTP/HTTPS traffic between the mobile app and the server. This allows you to view and modify the requests and responses in real-time.

Several free and commercial proxy tools are available. For example: @MASTG-TOOL-0097, @MASTG-TOOL-0077 and @MASTG-TOOL-0079.

## Rerouting Traffic to the Proxy

To use the interception proxy, you'll need to run it on your host computer and configure the mobile app to route HTTP(S) requests to your proxy. In most cases, it is enough to set a system-wide proxy in the network settings of the mobile device - if the app uses standard HTTP APIs or popular libraries such as `okhttp`, it will automatically use the system settings.

<img src="Images/Chapters/0x04f/BURP.png" width="100%" />

## Installing the Proxy Certificate

Using an interception proxy breaks SSL certificate verification and the app will usually fail to initiate TLS connections. Because of this, interception proxies require you to install a custom CA certificate on the mobile device, which allows the proxy to decrypt and inspect the encrypted HTTPS traffic. Depending on the platform, the installed certificate may or may not be automatically trusted by the application. Additionally, some apps implement certificate pinning, which requires additional effort to bypass.

## Per-Platform Instructions

- Android: see @MASTG-TECH-0011
- iOS: see @MASTG-TECH-0063
