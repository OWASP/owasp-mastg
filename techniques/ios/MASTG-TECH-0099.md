---
title: Intercepting Non-proxy-aware HTTP Traffic
platform: ios
---


Flutter is an open-source UI software development kit (SDK) created by Google. It is used for building natively compiled applications for mobile, web, and desktop from a single codebase. Flutter uses Dart, which is not proxy-aware and uses its own certificate store.The application doesn’t take proxy configuration from the system and send the data directly to the server.Due to this,it is not possible to intercept the request using the BurpSuite or any MITM tools.



## Intercepting Traffic using re-fultter

1. The re-Fultter supports both android and ios flutter applications.
2. Install the [reflutter](https://github.com/Impact-I/reFlutter.git).
3. Run the command to patch the application.
```
$ reflutter demo.ipa
```
4. It prompts to choose two options:
```
$ reflutter demo.ipa 

 Choose an option: 

 1. Traffic monitoring and interception 
 2. Display absolute code offset for functions

[1/2]? 
```
5. Select  the **Traffic monitoring and interception**.
6. It prompts **Please enter your BurpSuite IP**. Enter the **IP** of the machine which the BurpSuite is running.
```
$ reflutter demo.ipa 

 Choose an option: 

 1. Traffic monitoring and interception 
 2. Display absolute code offset for functions
 [1/2]? 1

Example: (192.168.1.154) etc.
Please enter your BurpSuite IP: 192.168.0.123
```
7. This will create a patched **release.RE.ipa** file.
```
SnapshotHash: 7dbbeeb8ef7bdfd91338640dca3927636de
The resulting ipa file: ./release.RE.ipa
Please install the ipa file

Configure Burp Suite proxy server to listen on *:8083
Proxy Tab -> Options -> Proxy Listeners -> Edit -> Binding Tab

Then enable invisible proxying in Request Handling Tab
Support Invisible Proxying -> true
``` 
8. [Re-sign](../../techniques/ios/MASTG-TECH-0092.md) the application with the Apple certificates.
9. Install the re-signed application on the mobile device.
10. Configure the Burp-suite:
    - Under Proxy -> Proxy settings -> Add new Proxy setting.
    - Bind listening Port to **8083**.
    - Select Bind to address to **All interfaces**. 
    - Request Handling -> support for invisible proxying.
11. Open the Application and start intercepting the requests from the applications.
