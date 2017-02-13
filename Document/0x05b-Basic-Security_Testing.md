## Basic Security Testing on Android

### Setting Up Your Testing Environment

#### Hardware

##### Rooting your device
-- TODO : Which devices can be used : Nexus / Pixel --
-- TODO : Boot Process Description --
-- TODO : Boot Loaders and ROMs--
-- TODO : Explain the restrictions in case a non-rooted device is used for testing


#### Emulator

##### Rooting an Android Virtual Device (AVD)
https://forum.xda-developers.com/showthread.php?t=2227815


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

#### Using an emulator

All of the above steps to prepare a hardware testing device do also apply if an emulator is used<sup>[4]</sup>. For dynamic testing several tools or VMs are available that can be used to test an App within an emulator environment:

* AppUse
* Drozer
* MobSF

There are several downsides when using an emulator. You might not be able to test an App properly in an emulator, if it's relying on the usage of a specific mobile network, or uses NFC or GPS. Testing within an emulator is usually also slower in nature and might lead to issues on it's own.


### References


- [1] Configuring an Android Device to Work With Burp - https://support.portswigger.net/customer/portal/articles/1841101-Mobile%20Set-up_Android%20Device.html
- [2] Installing Burp's CA Certificate in an Android Device - https://support.portswigger.net/customer/portal/articles/1841102-installing-burp-s-ca-certificate-in-an-android-device
- [3] Creating an Ad-hoc Wireless Network in OS X - https://support.portswigger.net/customer/portal/articles/1841150-Mobile%20Set-up_Ad-hoc%20network_OSX.html
- [4] Android Application Security Testing Guide: Part 2 - http://resources.infosecinstitute.com/android-app-sec-test-guide-part-2/#gref
