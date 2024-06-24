--- 
title: Intercepting Flutter HTTPS Traffic
platform: android 
---

Flutter is an open-source UI software development kit (SDK) created by Google. It is used for building natively compiled applications for mobile, web, and desktop from a single codebase. Flutter uses Dart, which is not proxy-aware and uses its own certificate store. The application doesn't use the proxy configuration of the system and sends the data directly to the server. Connections are verified against built-in certificates, so any certificates installed on the system are simply ignored. Due to this, it is not possible to intercept HTTPS requests as the certificate of the proxy will never be trusted.

In order to intercept Flutter HTTPS traffic, we need to deal with two problems:

- Make sure the traffic is sent to the proxy.
- Disable the TLS verification of any HTTPS connection.

There are generally two approaches to this: **reFlutter** and **Frida**.

- **reFlutter**: This tool creates a modified version of the Flutter module which is then repackaged into the APK. It configures the internal libraries to use a specified proxy and disable the TLS verification.
- **Frida**: The [disable-flutter-tls.js script](https://github.com/NVISOsecurity/disable-flutter-tls-verification) can dynamically remove the TLS verification without the need for repackaging. As it doesn't modify the proxy configuration, additional steps are needed (e.g. ProxyDroid, DNS, iptables, ...).

## Intercepting Traffic using reFlutter

1. Patch the app to enable traffic interception.

Run the command to patch the app and select the option **Traffic monitoring and interception** and then enter the IP of the machine on which the interception proxy is running.

```plaintext
$ reflutter demo.apk

Choose an option:

    Traffic monitoring and interception
    Display absolute code offset for functions

[1/2]? 1

Example: (192.168.1.154) etc.
Please enter your BurpSuite IP: 192.168.29.216
```

This will create a **release.RE.apk** file in the output folder.

2. Sign the patched **release.RE.apk** file (e.g. using the [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer)).

```bash
java -jar uber-apk-signer.jar -a release.RE.apk --out demo-signed
```

This will create a **release.RE-aligned-debugSigned.apk** file in the output folder.

3. Install the signed patched app on the mobile device.

4. Configure the interception proxy. For example, in Burp:

- Under Proxy -> Proxy settings -> Add new Proxy setting.
- Bind listening Port to `8083`.
- Select `Bind to address` to `All interfaces`.
- Request Handling -> support for invisible proxying.

5. Open the app and start intercepting traffic.

## Intercepting Traffic using ProxyDroid / iptables with Frida

1. Configure [proxyDroid](https://blog.nviso.eu/2019/08/13/intercepting-traffic-from-android-flutter-applications/) or iptables rules to redirect requests to Burp.

If not using proxyDroid, execute the following commands on the rooted Android device to configure iptables to redirect the incoming requests from the application to Burp:
```bash
$ iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination <Your-Proxy-IP>:8080 

$ iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination <Your-Proxy-IP>:8080 
```

2. Install the [app](../../apps/android/MASTG-APP-0016.md) on the mobile device.

3. Configure the interception proxy. For example, in Burp:

- Under Proxy -> Proxy settings -> Add new Proxy setting.
- Bind listening Port to `8080`.
- Select `Bind to address` to `All interfaces`.
- Request Handling -> support for invisible proxying.

4. Run the [disable-flutter-tls.js](../../tools/generic/MASTG-TOOL-0101.md) frida script.

```bash
frida -U -f eu.nviso.flutterPinning -l disable-flutter-tls.js
```

5. Start intercepting traffic.