## Basic Security Testing on Android

### Setting Up Your Testing Environment

When setting up the testing environment, this can become a challenging task. For example when testing on-site at client premises there might be restrictions when using an enterprise Access Point and ports are blocked making it more difficult to start a dynamic analysis of the App. Rooted phones might also not be allowed within the enterprise network due to companies policies. Also Root detection and other countermeasures can lead to significant extra work just to be able to finally test the App.

This section will give an overview of different methods on how an Android App can be tested and will illustrate also it's limitations. Due to the reasons stated above you should be aware of all possible testing methods to select the right one for your testing environment, but also to articulate restrictions so that everybody in the project is on the same page.

#### Preparation

The goal of a test is to verify if the App and the endpoint(s) it's communicating with, are implemented in a secure way. Several security controls like SSL Pinning or Root detection might be implemented that will slow down the testing dramatically and might already take days to bypass, depending on the implementation.

During the preparation phase it should be discussed with the company developing the mobile App, to provide two versions of the App. One App should be build as release to check if the implemented controls like SSL Pinning are working properly or can be easily bypassed and the same App should also be provided as debug build that deactivates certain security controls. Through this approach all scenarios and test cases can be tested in the most efficient way.

This approach need of course to align with the scope of the engagement and if it's a black box or white box test(Link to section in MSTG describing Black and White Box). For a white box test requesting for a production and debug build will help to be able to go through all test cases and give a clear statement of the security maturity of the App. For a black box test it might be already the intention of the client to see what can be done in a certain amount of time with the production App and how effective the implemented security controls are.

Either way, the following items should be discussed with the company developing the mobile App and it should be decided if the implemented security controls can be adjusted to get the best out of the testing exercise.  

##### SSL Pinning

SSL Pinning is already a strong mechanism to make dynamic analysis harder. Certificates provided by an interception proxy to enable a Man-in-the-middle position are declined and the App will not make any requests. To be able to efficiently test during a white box test, a debug build with deactivated SSL Pinning should be provided.

For a black box test, there are several ways to bypass SSL Pinning, for example [SSLUnpinning](https://github.com/ac-pm/SSLUnpinning_Xposed) or [Android-SSL-TrustKiller](https://github.com/iSECPartners/Android-SSL-TrustKiller). Therefore bypassing can be done within seconds, but only if the App uses the API functions that are covered for these tools. If the App is using a different framework or library to implement SSL Pinning that is not implemented yet in those tools, the patching and deactivation of SSL Pinning need to be done manually and can become time consuming.

To manually deactivate SSL Pinning there are two ways:
* Dynamical Patching while running the App, by using [Frida](https://www.frida.re/docs/android/) or [ADBI](https://github.com/crmulliner/adbi)
* Disassembling the APK, identify the SSL Pinning logic in smali code and patch it and reassemble the APK.  

See also test case "Testing Custom Certificate Stores and SSL Pinning" for further details.

##### Debug build

A debug build has several benefits, when provided during a (white box) test:
* Code obfuscation from ProGuard is not applied
* Debugger can be attached to the running App
**(..TODO..)**

See also test case "Testing If the App is Debuggable" for further details.

##### Root detection

To implement Root detection on Android several libraries are available like [RootBeer](https://github.com/scottyab/rootbeer). The approach for root detection is:
* Checking for default files, like verifying the BUILD tag for test-keys in the parameter `ro.build.tags`.
* Checking installed files and packages to identify a rooted device, like verifiying the presence of Superuser.apk
* Checking available commands, like is it possible to execute `su` and being root afterwards.
**(..TODO..)**

To be able to efficiently test during a white box test, a debug build with disabled root detection should be provided.

For a black box test in order to be able to start the tests, the root detection need to be bypassed. First the root detection mechanisms need to be identified and then disabled, either by dynamically patching the App or changes made to the test environment. This can be as easy as renaming the command that is used for root detection (renaming `su` to `su0`), but can become difficult if several different checks are part of the root detection mechanism.  Dynamically patching the App can also become difficult if countermeasures are implemented that prevent runtime manipulation.
**(..TODO..)**

See also test case "Testing Root Detection" and "Testing Advanced Root Detection" for further details.


#### Hardware

##### Rooting your device

-- TODO : Which devices can be used : Nexus / Pixel --
-- TODO : Boot Process Description --
-- TODO : Boot Loaders and ROMs--

##### Restrictions when using a non-rooted device

When using a non-rooted Android device it is still possible to execute dynamic analysis of the App.
**(..TODO..)**


#### Emulator

##### Rooting an Android Virtual Device (AVD)

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

There are several downsides when using an emulator. You might not be able to test an App properly in an emulator, if it's relying on the usage of a specific mobile network, or uses NFC or Bluetooth. Testing within an emulator is usually also slower in nature and might lead to issues on it's own.

Nevertheless several hardware characteristics can be emulated, like GPS<sup>[6]</sup> or SMS<sup>[7]</sup> and many more.


#### Software
-- TODO : Existing testing tools & tool suites : proxies, fuzzers, debuggers, vulnerability scanners, ... Most common tools : Binwalk, apktool, Dex2Jar, jad, Drozer, IDA --
-- TODO: Link to testing tools section


### Attack Methodology
-- TODO : Cf testing methodologies from CEH, ... : map attack surface (Local and Remote) through Passive and Active Reconnaissance, Scanning, Gaining Access, Maintaining Access, Covering Tracks. As this is generic and common to iOS, may be part of the parent chapter --

### Static Analysis
-- TODO : Description, when it comes compared to dynamic analysis and why, what it can bring --

#### With Source Code ("White box")
-- TODO : Description of the methodology, pros and cons (what can be done / not done, related tools, vulnerabilities that can be found) --

#### Without Source Code ("Black box")
-- TODO : Description of the methodology, pros and cons (what can be done / not done, related tools, vulnerabilities that can be found) --

### Dynamic Analysis

Compared to static analysis, dynamic analysis is applied while executing the mobile App. The test cases can range from investigating the file system and changes made to it on the mobile device or monitoring the communication with the endpoint while using the App.

When we are talking about dynamic analysis of applications that rely on the HTTP(S) protocol, several tools can be used to support the dynamic analysis. The most important tools are so called interception proxies, like OWASP ZAP, Burp Suite Professional or Fiddler to name the most famous ones. An interception proxy allows the tester to have a Man-in-the-middle position, in order to read and/or modify all requests made from the App and responses made from the endpoint.

#### Using a hardware device

Different preparation steps need to be applied before a dynamic analysis of a mobile App can be started. Ideally the device is rooted, as otherwise some test cases cannot be tested properly. See "Rooting your device" for more information.

The available setup options for the network need to be evaluated first. The mobile device used for testing and the machine running the interception proxy need to be placed within the same WiFi network. Either an (existing) access point is used or an ad-hoc wireless network is created<sup>[3]</sup>.

Once the network is configured and connectivity is established between the testing machine and the mobile device several other steps need to be done.

* The proxy in the network settings of the WiFi connection of the Android device need to configured properly to point to the interception proxy in use<sup>[1]</sup>.
* The CA certificate of the interception proxy need to be added to the trusted certificates in the certificate storage <sup>[2]</sup> of the Android device. Due to different versions of Android and modifications of Android OEMs to the settings menu, the location of the menu to store a CA might differ.

After finishing this steps and starting the App the requests should show up in the interception proxy.

#### Using an emulator

All of the above steps to prepare a hardware testing device do also apply if an emulator is used<sup>[4]</sup>. For dynamic testing several tools or VMs are available that can be used to test an App within an emulator environment:

* AppUse
* MobSF

It is also possible to simply create an AVD and use this for testing.


### References


- [1] Configuring an Android Device to Work With Burp - https://support.portswigger.net/customer/portal/articles/1841101-Mobile%20Set-up_Android%20Device.html
- [2] Installing Burp's CA Certificate in an Android Device - https://support.portswigger.net/customer/portal/articles/1841102-installing-burp-s-ca-certificate-in-an-android-device
- [3] Creating an Ad-hoc Wireless Network in OS X - https://support.portswigger.net/customer/portal/articles/1841150-Mobile%20Set-up_Ad-hoc%20network_OSX.html
- [4] Android Application Security Testing Guide: Part 2 - http://resources.infosecinstitute.com/android-app-sec-test-guide-part-2/#gref
- [5] Create and Manage Virtual Devices - https://developer.android.com/studio/run/managing-avds.html
- [6] GPS Emulation - https://developer.android.com/studio/run/emulator-commandline.html#geo
- [7] SMS Emulation - https://developer.android.com/studio/run/emulator-commandline.html#sms
