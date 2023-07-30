---
title: Information Gathering - Network Communication
platform: android
---

Most of the apps you might encounter connect to remote endpoints. Even before you perform any dynamic analysis (e.g. traffic capture and analysis), you can obtain some initial inputs or entry points by enumerating the domains to which the application is supposed to communicate to.

Typically these domains will be present as strings within the binary of the application. One way to achieve this is by using automated tools such as [APKEnum](https://github.com/shivsahni/APKEnum "APKEnum: A Python Utility For APK Enumeration") or [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF "MobSF"). Alternatively, you can _grep_ for the domain names by using regular expressions. For this you can target the app binary directly or reverse engineer it and target the disassembled or decompiled code. The latter option has a clear advantage: it can provide you with **context**, as you'll be able to see in which context each domain is being used (e.g. class and method).

From here on you can use this information to derive more insights which might be of use later during your analysis, e.g. you could match the domains to the pinned certificates or the [Network Security Configuration](0x05g-Testing-Network-Communication.md#android-network-security-configuration) file or perform further reconnaissance on domain names to know more about the target environment. When evaluating an application it is important to check the Network Security Configuration file, as often (less secure) debug configurations might be pushed into final release builds by mistake.

The implementation and verification of secure connections can be an intricate process and there are numerous aspects to consider. For instance, many applications use other protocols apart from HTTP such as XMPP or plain TCP packets, or perform certificate pinning in an attempt to deter MITM attacks but unfortunately have severe logical bugs in its implementation or an inherently wrong security network configuration.

Remember that in most of the cases, just using static analysis will not be enough and might even turn to be extremely inefficient when compared to the dynamic alternatives which will get much more reliable results (e.g. using an interceptor proxy). In this section we've just slightly touched the surface, please refer to the section "[Basic Network Monitoring/Sniffing](0x05b-Basic-Security_Testing.md#basic-network-monitoringsniffing "Basic Network Monitoring/Sniffing")" in the "Android Basic Security Testing" chapter and also check the test cases in the "[Android Network Communication](0x05g-Testing-Network-Communication.md)" chapter.
