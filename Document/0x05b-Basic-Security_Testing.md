## Basic Security Testing on Android

### Setting Up Your Testing Environment

When setting up the testing environment, this can become a challenging task. For example when testing on-site at client premises there might be restrictions when using an enterprise Access Point due to limitations in the connections that can be made (e.g. ports are blocked), making it more difficult to start a dynamic analysis of the app. Rooted phones might also not be allowed within the enterprise network due to companies policies. Also, root detection and other countermeasures implemented within an app can lead to significant extra work just to be able to finally test the app. Either way, the testing team responsible for the Android assessment need to work together with the app developer(s) and operation team in order to find a proper solution for a working testing environment.

This section will give an overview of different methods on how an Android app can be tested and will illustrate also its limitations. Due to the reasons stated above you should be aware of all possible testing methods to select the right one for your testing environment, but also to articulate restrictions so that everybody in the project is on the same page.

#### Preparation

The goal of a test is to verify if the app and the endpoint(s) it's communicating with, are implemented in a secure way. Several security controls like SSL Pinning or root detection might be implemented. These will slow down the testing dramatically and might already take days to bypass, depending on the implementation.

During the preparation phase it should be discussed with the company developing the mobile app, to provide two versions of the app. One app should be built as release to check if the implemented controls like SSL Pinning are working properly or can be easily bypassed. The same app should also be provided as debug build that deactivates certain security controls. Through this approach all scenarios and test cases can be tested in the most efficient way.

This approach needs of course to align with the scope of the engagement and if it's a black box or white box test (-- TODO [Link to section in MSTG describing Black and White Box] --). For a white box test, requesting for a production and debug build will help to go through all test cases and give a clear statement of the security maturity of the app. For a black box test it might be already the intention of the client to see what can be done in a certain amount of time with the production app and how effective the implemented security controls are.

Either way, the following items should be discussed with the company developing the mobile app and it should be decided if the implemented security controls can be adjusted to get the best out of the testing exercise.  

##### SSL Pinning

SSL Pinning is already a strong mechanism to make dynamic analysis harder. Certificates provided by an interception proxy to enable a Man-in-the-middle position are declined and the app will not make any requests. To be able to efficiently test during a white box test, a debug build with deactivated SSL Pinning should be provided.

For a black box test, there are several ways to bypass SSL Pinning, for example SSLUnpinning<sup>[11]</sup> or Android-SSL-TrustKiller<sup>[12]</sup>. Therefore bypassing can be done within seconds, but only if the app uses the API functions that are covered for these tools. If the app is using a different framework or library to implement SSL Pinning that is not implemented yet in those tools, the patching and deactivation of SSL Pinning needs to be done manually and can become time consuming.

To manually deactivate SSL Pinning there are two ways:
* Dynamical Patching while running the App, by using Frida<sup>[9] [13]</sup> or ADBI<sup>[10]</sup>
* Disassembling the APK, identify the SSL Pinning logic in smali code, patch it and reassemble the APK<sup>[7] [22]</sup>

Once successful, the prerequisites for a dynamic analysis are met and the apps communication can be investigated.

See also test case "Testing Custom Certificate Stores and SSL Pinning" **(-- TODO [add_link] --)** for further details.

##### Debug Build

A debug build has several benefits, when provided during a (white box) test that allows a more comprehensive analysis:
* Debugger can be attached to the running App
* Debug log files of the App are available

-- TODO [Elaborate on Debug Build] --

See also test case "Testing If the app is Debuggable" **(-- TODO [add_link] --)** for further details.

##### OS versions
Before starting to test any application, it is important to have all the required hardware and software. This does not only mean that you must have a configured machine ready to run auditing tools, but also that you have the correct version of the Android OS installed on both the machine and the device. Therefore, it is always recommended to ask if the application runs only on specific versions of Android OS. 

##### Root detection

To implement root detection on Android, libraries like RootBeer<sup>[14]</sup> or custom checks are used to verify if the device is rooted or not. See also test case "Testing Root Detection" **(-- TODO [add_link] --)** and "Testing Advanced Root Detection" for further details.

To be able to efficiently test during a white box test, a debug build with disabled root detection should be provided.

##### Tampering

Another security control available in mobile apps, is checking if the app has been tampered. This means that checks are in place to prevent repackaging the app. For example: to deactivate SSL Pinning in a black box test or to dynamically patch the app while running with frameworks like Frida. Both ways of tampering can be detected and might forbid to run the app if tampering is detected.

To be able to efficiently test during a white box test, a debug build with disabled tampering checks should be provided.

See also "Verifying the Variability of Tampering Responses" **(-- TODO [add_link] --)** for further details.

#### Hardware

##### Rooting your device

###### Risks of rooting your device

As a security tester, you may want to root your mobile device: while some tests can be performed on a non-rooted mobile, some do require a rooted one. However, you need to be aware of the fact that rooting is not an easy process and requires advanced knowledge. Rooting is risky, and three main consequences need to be clarified before you may proceed: rooting
* usually voids the device guarantee (always check the manufacturer policy before taking any action),
* may "brick" the device, e.g. render it unoperable and unusable.
* brings additional security risks as built-in exploit mitigations are often removed.

** You need to understand that rooting your device is ultimately YOUR own decision and that OWASP shall in no way be help responsible for any damage. In case you feel unsure, always seek expert advice before starting the rooting process. **

###### Which mobiles can be rooted?

Virtually, any Android mobile can be rooted. Commercial versions of Android OS, at the kernel level, evolutions of Linux OS, are optimized for the mobile world. Here some features are removed or disabled, such as the possibility for a non-privileged user to become the 'root' user (which has elevated privileges). Rooting a phone means adding the feature to become the root user, e.g. technically speaking adding a standard Linux executable called 'su' used for switching users.

The first step in rooting a mobile is to unlock its boot loader. The procedure depends on each manufacturer. However, for practical reasons, rooting some mobiles is more popular than rooting others, particularly when it comes to security testing: devices created by Google (and manufactured by other companies like Samsung, LG and Motorola) are among the most popular, particularly because they are widely used by developers. The device warranty is not nullified when the boot loader is unlocked and Google provides many tools to support the root itself to work with rooted devices. A curated list of guide on rooting devices from all major brands can be found xda forums<sup>[21]</sup>.

See also "Android Platform Overview" for further details.

##### Restrictions when using a non-rooted device

For testing of an Android app a rooted device is the foundation for a tester to be able to execute all available test cases. In case a non-rooted device need to be used, it is still possible to execute several test cases to the app.

Nevertheless, this highly depends on the restrictions and settings made in the app. For example if backups are allowed, a backup of the data directory of the app can be extracted. This allows detailed analysis of leakage of sensitive data when using the app. Also if SSL Pinning is not used a dynamic analysis can also be executed on a non-rooted device.  


#### Emulator

##### Connecting to an Android Virtual Device (AVD) as Root

An Android Virtual Device (AVD) can be created by using the AVD manager, which is available within Android Studio<sup>[5]</sup>. The AVD manager can also be started separately from the command line by using the `android` command in the tools directory of the Android SDK:

```bash
$ ./android avd
```

Once the emulator is up and running a root connection can be established by using `adb`.

```bash
$ adb root
$ adb shell
root@generic_x86:/ $ id
uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats) context=u:r:su:s0
```

Rooting of an emulator is therefore not needed as root access can be granted through `adb`.


##### Restrictions when testing with an emulator

There are several downsides when using an emulator. You might not be able to test an app properly in an emulator, if it's relying on the usage of a specific mobile network, or uses NFC or Bluetooth. Testing within an emulator is usually also slower in nature and might lead to issues on its own.

Nevertheless several hardware characteristics can be emulated, like GPS<sup>[6]</sup> or SMS<sup>[7]</sup> and many more.


#### Software and Tools (non-comprehensive list)

The context of mobile security testing is a conjunction of multiple different tier of components: **application container**, **communications** and **back-end servers**. These three high-level attack surface will be the main attack surface for a mobile security testing.   

* **Application container:**  insecure data storage, poor resiliency against reverse engineering and etc.
* **Communication:** usage of insecure or unencrypted communication channel, missing certification pinning and etc.
* **Back-end Servers:** flawed authentication or security logic, vulnerable server side functions and etc.

There are various tool that can be leverage to conduct an effective mobile security testing and like any tool of choice it all depends on the matter of preference and budget. Some basic usage of tools will be covered in the following section and an extensive list of tools can be found in "Testing Tools" **(-- TODO [add_link] --)** page.

#####Network Analysis
A proxy is the bread and butter to any form of security testing that involves a client-server application and that includes mobile application. It can be used to intercept network traffic between a mobile and a back-end server for testing Authorization, Session Management and so on. Some popular proxy tools for security testings are Burp Suite, OWASP ZAP and Charles.

##### Reverse Engineering and Static Analysis
There are many reason to reverse engineer an application: to understand application security logic, to identify application secret and so on. More detail coverage on reverse engineering Android application are covered in "Tampering and Reverse Engineering on Android" **(-- TODO [add_link] --)** page. Some popular tools that will be used are apktool, enjarify and more.

##### Dynamic and run time analysis
The goals here are to retrieve code, execute the application and test its behavior dynamically, to change its flow, manipulate the memory of the mobile and so on. Partial information about dynamic and run time analysis will be covered in "Tampering and Reverse Engineering on Android" **(-- TODO [add_link] --)**. Some popular tools will be frida, Cydia Substrate, drozer.

### Static Analysis

Static analysis is the act of looking into app components, source code and other resources without actually executing it. This test is focused on finding misconfigured or unprotected Android IPC components, as well as finding programming mistakes such as misuse of cryptography routines, find libraries with known vulnerabilities and even dynamic code loading routines.

Static analysis should be supported through the usage of tools, to make the analysis efficient and to allow the tester to focus on the more complicated business logic. There are a plethora of static code analyzers that can be used, ranging from open source scanners to full blown enterprise ready scanners. The decision on which tool to use depends on the budget, requirements by the client and the preferences of the tester.

Some Static Analyzers rely on the availability of the source code while others take the compiled apk as input.
It is important to keep in mind that while static analyzers can help us to focus attention on potential problems, they may not be able to find all the problems by itself. Go through each finding carefully and try to understand what the app is doing to improve your chances of finding vulnerabilities.

One important thing to note is to configure the static analyser properly in order to reduce the likelihood of false positives and maybe only select several vulnerability categories in the scan. The results generated by static analysers can otherwise be overwhelming and the effort can become counterproductive if an overly large report need to be manually investigated.

Static Analysis can be divided into two categories, **White box** and **Black box**. The first is when the source code is available and the other is when we only have the compiled application or library. We will now go into more details on each category.

#### With Source Code ("White box")

**White box testing** an app is the act of testing an app with the source code available. To accomplish the source code testing, you will want to have a setup similar to the developer. You will need a computer with the Android SDK and an IDE installed. It is also recommended to that you have access to either a physical device or an emulator, so you can debug the app.

Once you have the setup ready and the source code indexed by an IDE (Android Studio is recommended since it is the current IDE of choice by Google), you can start debugging and searching for interesting parts of code.
Begin by testing each [Android Component](0x05a-Platform-Overview.md#app-components). Check whether they are exported and the enforcing permissions that are in place. Android Lint<sup>[15]</sup> can help in the identification of such problems.

Any Android component manipulating sensitive data (contacts, location, images, etc.) should be investigated carefully.

Proceed on to testing the libraries the application has embedded: some libraries contain known vulnerabilities and you should check for that. Some of the question you may want to answer are: what libraries are the app using? Which version of the libraries are being used? Do they have any known vulnerability?

Since you have the source code in hand, you can check for crypto mistakes in the implementation. Look for hard coded keys and implementation errors related to cryptography functions. Devknox<sup>[16]</sup> can help checking most common cryptographic mistakes since it is embedded to the IDE.

#### Without Source Code ("Black box")

During a **Black box testing** you will not have access to the source code in its original form. Usually, you will have the application package in hand (in Android .apk format<sup>[17]</sup>), which can be installed on an Android device or reverse engineered with the goal to retrieve parts of the source code.

If the application is based solely on Java and does not have any native library (code written in C/C++), the reverse engineering process is relatively easy and recovers almost the entire source code. Applications that contain a native library can still be reverse engineered by require low level knowledge and the process is not automated.

More details and tools about the Android reverse engineering topic can be found at [Tampering and Reverse Engineering on Android](0x05b-Reverse-Engineering-and-Tampering.md) section.

Besides reverse engineering, there is a handful of automated tools that perform security analysis on the APK itself searching for vulnerabilities.
Some of these tools are: QARK<sup>[18]</sup>, Androbugs<sup>[19]</sup> and JAADAS<sup>[20]</sup>.

### Dynamic Analysis

Compared to static analysis, dynamic analysis is applied while executing the mobile app. The test cases can range from investigating the file system and changes made to it on the mobile device or monitoring the communication with the endpoint while using the app.

When we talk about dynamic analysis of applications that rely on the HTTP(S) protocol, several tools can be used to support the dynamic analysis. The most important tools are so called interception proxies, like OWASP ZAP, Burp Suite Professional or Fiddler to name the most famous ones. An interception proxy allows the tester to have a Man-in-the-middle position, in order to read and/or modify all requests made from the app and responses made from the endpoint.

#### Using a hardware device

Different preparation steps need to be applied before a dynamic analysis of a mobile app can be started. Ideally the device is rooted, as otherwise some test cases cannot be tested properly. See "Rooting your device" for more information.

The available setup options for the network need to be evaluated first. The mobile device used for testing and the machine running the interception proxy need to be placed within the same WiFi network. Either an (existing) access point is used or an ad-hoc wireless network is created<sup>[3]</sup>.

Once the network is configured and connectivity is established between the testing machine and the mobile device, several other steps need to be done.

* The proxy in the network settings of the WiFi connection of the Android device need to be configured properly to point to the interception proxy in use<sup>[1]</sup>.
* The CA certificate of the interception proxy need to be added to the trusted certificates in the certificate storage <sup>[2]</sup> of the Android device. Due to different versions of Android and modifications of Android OEMs to the settings menu, the location of the menu to store a CA might differ.

After finishing these steps and starting the app, the requests should show up in the interception proxy.


#### Using an emulator

All of the above steps to prepare a hardware testing device do also apply if an emulator is used<sup>[4]</sup>. For dynamic testing several tools or VMs are available that can be used to test an app within an emulator environment:

* AppUse
* MobSF

It is also possible to simply create an AVD and use this for testing.

-- TODO [Develop section Using an Emulator : what can be done with it, difference with using a real Android mobile, availability, how to start and configure one] --

### References


- [1] Configuring an Android Device to Work With Burp - https://support.portswigger.net/customer/portal/articles/1841101-Mobile%20Set-up_Android%20Device.html
- [2] Installing Burp's CA Certificate in an Android Device - https://support.portswigger.net/customer/portal/articles/1841102-installing-burp-s-ca-certificate-in-an-android-device
- [3] Creating an Ad-hoc Wireless Network in OS X - https://support.portswigger.net/customer/portal/articles/1841150-Mobile%20Set-up_Ad-hoc%20network_OSX.html
- [4] Android Application Security Testing Guide: Part 2 - http://resources.infosecinstitute.com/android-app-sec-test-guide-part-2/#gref
- [5] Create and Manage Virtual Devices - https://developer.android.com/studio/run/managing-avds.html
- [6] GPS Emulation - https://developer.android.com/studio/run/emulator-commandline.html#geo
- [7] SMS Emulation - https://developer.android.com/studio/run/emulator-commandline.html#sms
- [8] Mobile Security Certificate Pinning -  http://blog.dewhurstsecurity.com/2015/11/10/mobile-security-certificate-pining.html
- [9] Frida - https://www.frida.re/docs/android/
- [10] ADBI - https://github.com/crmulliner/adbi
- [11] SSLUnpinning - https://github.com/ac-pm/SSLUnpinning_Xposed
- [12] Android-SSL-TrustKiller - https://github.com/iSECPartners/Android-SSL-TrustKiller
- [13] Defeating SSL Pinning in Coin's Android Application -  http://rotlogix.com/2015/09/13/defeating-ssl-pinning-in-coin-for-android/
- [14] RootBeet - https://github.com/scottyab/rootbeer
- [15] Android Lint - https://sites.google.com/a/android.com/tools/tips/lint/
- [16] devknox - https://devknox.io/
- [17] Android application package - https://en.wikipedia.org/wiki/Android_application_package
- [18] QARK - https://github.com/linkedin/qark/
- [19] Androbugs - https://github.com/AndroBugs/AndroBugs_Framework
- [20] JAADAS - https://github.com/flankerhqd/JAADAS
- [21] Guide to root mobile devices - https://www.xda-developers.com/root/
- [22] Bypassing SSL Pinning in Android Applications - https://serializethoughts.com/2016/08/18/bypassing-ssl-pinning-in-android-applications/
