---
title: Bypassing Certificate Pinning
platform: ios
---

Some applications will implement SSL Pinning, which prevents the application from accepting your intercepting certificate as a valid certificate. This means that you will not be able to monitor the traffic between the application and the server.

For most applications, certificate pinning can be bypassed within seconds, but only if the app uses the API functions that are covered by these tools. If the app is implementing SSL Pinning with a custom framework or library, the SSL Pinning must be manually patched and deactivated, which can be time-consuming.

This section describes various ways to bypass SSL Pinning and gives guidance about what you should do when the existing tools don't work.

## Methods for Jailbroken and Non-jailbroken Devices

If you have a jailbroken device with frida-server installed, you can bypass SSL pinning by running the following @MASTG-TOOL-0038 command (see @MASTG-TECH-0090 if you're using a non-jailbroken device):

```bash
ios sslpinning disable
```

Here's an example of the output:

<img src="Images/Chapters/0x06b/ios_ssl_pinning_bypass.png" width="100%" />

See also [Objection's help on Disabling SSL Pinning for iOS](https://github.com/sensepost/objection/blob/master/objection/console/helpfiles/ios.sslpinning.disable.txt) for further information and inspect the [pinning.ts](https://github.com/sensepost/objection/blob/master/agent/src/ios/pinning.ts "pinning.ts") file to understand how the bypass works.

## Methods for Jailbroken Devices Only

If you have a jailbroken device you can try one of the following tools that can automatically disable SSL Pinning:

- "[SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2 "SSL Kill Switch 2")" is one way to disable certificate pinning. It can be installed via the @MASTG-TOOL-0047 store. It will hook on to all high-level API calls and bypass certificate pinning.
- The @MASTG-TOOL-0077 app can also be used to bypass certificate pinning.

## When the Automated Bypasses Fail

Technologies and systems change over time, and some bypass techniques might not work eventually. Hence, it's part of the tester work to do some research, since not every tool is able to keep up with OS versions quickly enough.

Some apps might implement custom SSL pinning methods, so the tester could also develop new bypass scripts making use of existing ones as a base or inspiration and using similar techniques but targeting the app's custom APIs. Here you can inspect three good examples of such scripts:

- ["objection - Pinning Bypass Module" (pinning.ts)](https://github.com/sensepost/objection/blob/master/agent/src/ios/pinning.ts)
- ["Frida CodeShare - ios10-ssl-bypass"](https://codeshare.frida.re/@dki/ios10-ssl-bypass/) by @dki
- ["Circumventing SSL Pinning in obfuscated apps with OkHttp"](https://blog.nviso.eu/2019/04/02/circumventing-ssl-pinning-in-obfuscated-apps-with-okhttp) by Jeroen Beckers

**Other Techniques:**

If you don't have access to the source, you can try binary patching:

- If OpenSSL certificate pinning is used, you can try binary patching.
- Sometimes, the certificate is a file in the application bundle. Replacing the certificate with Burp's certificate may be sufficient, but beware of the certificate's SHA sum. If it's hardcoded into the binary, you must replace it too!
- If you can access the source code you could try to disable certificate pinning and recompile the app, look for API calls for `NSURLSession`, `CFStream`, and `AFNetworking` and methods/strings containing words like "pinning", "X.509", "Certificate", etc.
