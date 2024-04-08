--- 
title: Intercepting Non-proxy-aware Requests
platform: android 
---

Flutter is an open-source UI software development kit (SDK) created by Google. It is used for building natively compiled applications for mobile, web, and desktop from a single codebase. Flutter uses Dart, which is not proxy-aware and uses its own certificate store.The application doesn’t take proxy configuration from the system and send the data directly to the server.Due to this , it is not possible to intercept the request using the Burp-suite or any MITM tools.

## Intercepting Traffic using re-flutter

1. The re-fultter supports both android and ios flutter applications.
2. Install the [reflutter](https://github.com/Impact-I/reFlutter.git).
3. Run the command to patch the application.
```
$ reflutter demo.apk
```
4. It prompts to choose two options:
```
$ reflutter demo.apk

 Choose an option: 

 1. Traffic monitoring and interception 
 2. Display absolute code offset for functions

 [1/2]? 
```
5. Select the **Traffic monitoring and interception**.
6. Then it prompts **“Please enter your BurpSuite IP”**.Enter the IP of the machine which the burp suite is running.
```
$ reflutter demo.apk 

  Choose an option: 

 1. Traffic monitoring and interception 
 2. Display absolute code offset for functions

 [1/2]? 1

Example: (192.168.1.154) etc.
Please enter your BurpSuite IP: 192.168.29.216
```
7. This will create a patched **release.RE.apk** file.
8. Re-sign the application with the [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer).
```bash
$ java -jar uber-apk-signer.jar -a release.RE.apk --out demo-signed
```
9. This will create a **release.RE-aligned-debugSigned.apk** file in the output folder.
10. Install the re-signed application on the mobile device.
11. Configure the Burp-suite:
    - Under Proxy -> Proxy settings -> Add new Proxy setting.
    - Bind listening Port to **8083**.
    - Select Bind to address to **All interfaces**.
    - Request Handling -> support for invisible proxying.
12. Open the Application and start intercepting the requests from the applications.