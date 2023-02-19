---
title: Burp Suite
platform: network
---

Burp Suite is an integrated platform for performing security testing mobile and web applications - <https://portswigger.net/burp/releases>

Its tools work together seamlessly to support the entire testing process, from initial mapping and analysis of attack surfaces to finding and exploiting security vulnerabilities. Burp Proxy operates as a web proxy server for Burp Suite, which is positioned as a man-in-the-middle between the browser and web server(s). Burp Suite allows you to intercept, inspect, and modify incoming and outgoing raw HTTP traffic.

Setting up Burp to proxy your traffic is pretty straightforward. We assume that both your device and host computer are connected to a Wi-Fi network that permits client-to-client traffic.

PortSwigger provides good tutorials on setting up both Android as iOS devices to work with Burp:

- [Configuring an Android Device to Work With Burp](https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp "Configuring an Android Device to Work With Burp").
- [Installing Burp's CA certificate to an Android device](https://support.portswigger.net/customer/portal/articles/1841102-installing-burp-s-ca-certificate-in-an-android-device "Installing Burp\'s CA Certificate in an Android Device").
- [Configuring an iOS Device to Work With Burp](https://support.portswigger.net/customer/portal/articles/1841108-configuring-an-ios-device-to-work-with-burp "Configuring an iOS Device to Work With Burp").
- [Installing Burp's CA certificate to an iOS device](https://support.portswigger.net/customer/portal/articles/1841109-installing-burp-s-ca-certificate-in-an-ios-device "Installing Burp\'s CA Certificate in an iOS Device").

Please refer to the section "Setting up an Interception Proxy" in the [Android](0x05b-Basic-Security_Testing.md#setting-up-an-interception-proxy "Setting up an Interception Proxy") and [iOS](0x06b-Basic-Security-Testing.md#setting-up-an-interception-proxy "Setting up an Interception Proxy") "Basic Security Testing" chapters for more information.