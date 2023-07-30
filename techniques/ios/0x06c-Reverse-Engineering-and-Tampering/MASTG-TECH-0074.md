---
title: Information Gathering - Network Communication
platform: ios
---

Most of the apps you might encounter connect to remote endpoints. Even before you perform any dynamic analysis (e.g. traffic capture and analysis), you can obtain some initial inputs or entry points by enumerating the domains to which the application is supposed to communicate to.

Typically these domains will be present as strings within the binary of the application. One can extract domains by retrieving strings (as discussed above) or checking the strings using tools like Ghidra. The latter option has a clear advantage: it can provide you with context, as you'll be able to see in which context each domain is being used by checking the cross-references.

From here on you can use this information to derive more insights which might be of use later during your analysis, e.g. you could match the domains to the pinned certificates or perform further reconnaissance on domain names to know more about the target environment.

The implementation and verification of secure connections can be an intricate process and there are numerous aspects to consider. For instance, many applications use other protocols apart from HTTP such as XMPP or plain TCP packets, or perform certificate pinning in an attempt to deter MITM attacks.

Remember that in most cases, using only static analysis will not be enough and might even turn out to be extremely inefficient when compared to the dynamic alternatives which will get much more reliable results (e.g. using an interception proxy). In this section we've only touched the surface, so please refer to the section "[Basic Network Monitoring/Sniffing](0x06b-Basic-Security-Testing.md#basic-network-monitoringsniffing "Basic Network Monitoring/Sniffing")" in the "iOS Basic Security Testing" chapter and check out the test cases in the chapter "[iOS Network Communication](0x06g-Testing-Network-Communication.md)" for further information.
