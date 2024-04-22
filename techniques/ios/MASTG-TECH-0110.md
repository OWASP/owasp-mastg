---
title: Intercepting Flutter HTTP Traffic
platform: ios
---

Flutter is an open-source UI software development kit (SDK) created by Google. It is used for building natively compiled applications for mobile, web, and desktop from a single codebase. Flutter uses Dart, which is not proxy-aware and uses its own certificate store. The application doesn't take proxy configuration from the system and send the data directly to the server. Due to this, it is not possible to intercept the request using the BurpSuite or any MITM tools.


**How does re-flutter method differs from other techniques ?**

There are alternative methods for intercepting traffic, such as creating a [WIFI hotspot and utilizing the openvpn approach](https://blog.nviso.eu/2020/06/12/intercepting-flutter-traffic-on-ios/). However, these techniques require some configuration. By employing the re-flutter command-line tool, the application can be patched effortlessly without the need for any setup.

## Intercepting Traffic using re-fultter

1. Patch the app to enable traffic interception.

Run the command to patch the app and select the option **Traffic monitoring and interception** and then the IP of the machine which the interception proxy is running.
```
$ reflutter demo.apk

Choose an option:

    Traffic monitoring and interception
    Display absolute code offset for functions

[1/2]? 1

Example: (192.168.1.154) etc.
Please enter your BurpSuite IP: 192.168.29.216
```

This will create a **release.RE.ipa** file in the output folder.

2. [Sign](../../techniques/ios/MASTG-TECH-0092.md) the patched **release.RE.ipa** with the Apple certificates. This will create a singed ".ipa" file in the output folder.

3. Install the signed patched app on the mobile device.

4. Configure the interception proxy.For example, in Burp-suite:
  - Under Proxy -> Proxy settings -> Add new Proxy setting.
  - Bind listening Port to 8083.
  - Select Bind to address to All interfaces.
  - Request Handling -> support for invisible proxying.

5. Open the app and start intercepting traffic.
