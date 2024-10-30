--- 
title: Intercepting Flutter HTTPS Traffic
platform: android 
---

Flutter is an open-source UI software development kit (SDK) created by Google. It is used to build natively compiled applications for mobile, web, and desktop from a single codebase. Flutter uses Dart, which is not proxy-aware and uses its own certificate store. A Flutter mobile app doesn't use the system's proxy configuration and sends the data directly to the server. Connections are verified against built-in certificates, so any certificates installed on the system are simply ignored. This makes it impossible to intercept HTTPS requests through a standard MiTM setup, as the proxy's certificate is never trusted.

To intercept HTTPS traffic from a Flutter app, we have to deal with two challenges:

- Ensure that the traffic is sent to the proxy.
- Disable TLS verification on any HTTPS connection.

There are generally two approaches to this: **@MASTG-TOOL-0100** and **@MASTG-TOOL-0001**.

- **reFlutter**: This tool creates a modified version of the Flutter module which is then repackaged into the APK. It configures the internal libraries to use a specified proxy and disables the TLS verification.
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

2. Sign the patched **release.RE.apk** file (e.g. using @MASTG-TOOL-0103).

    ```bash
    java -jar uber-apk-signer.jar -a release.RE.apk --out demo-signed
    ```

    This will create a **release.RE-aligned-debugSigned.apk** file in the output folder.

3. Install the signed patched app on the mobile device.

4. Configure the interception proxy. For example, in @MASTG-TOOL-0077:

   - Under Proxy -> Proxy settings -> Add new Proxy setting.
   - Bind listening Port to `8083`.
   - Select `Bind to address` to `All interfaces`.
   - Request Handling -> support for invisible proxying.

5. Open the app and start intercepting traffic.

## Intercepting Traffic using ProxyDroid / iptables with Frida

You can either configure @MASTG-TOOL-0120 or create `iptables` rules to redirect HTTP requests to Burp.

- If you are not using proxyDroid, execute the following commands on the rooted Android device to configure `iptables` to redirect the incoming requests from the application to @MASTG-TOOL-0077:

    ```bash
    $ iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination <Your-Proxy-IP>:8080 

    $ iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination <Your-Proxy-IP>:8080 
    ```

- Configure the interception proxy, like @MASTG-TOOL-0077:

    - Under Proxy -> Proxy settings -> Add new Proxy setting.
    - Bind listening Port to `8080`.
    - Select `Bind to address` to `All interfaces`.
    - Request Handling -> support for invisible proxying.

- Run the @MASTG-TOOL-0101 Frida script.

     ```bash
     $ frida -U -f eu.nviso.flutterPinning -l disable-flutter-tls.js
     ```

- Use the app and you should be able to intercept HTTP traffic of the Flutter app.

Further explanations for this setup can be found in the blog post from [Nviso](https://blog.nviso.eu/2019/08/13/intercepting-traffic-from-android-flutter-applications/).
