# Introduction to the OWASP Mobile Application Security Project

New technology always introduces new security risks, and security concerns for mobile apps differ from traditional desktop software in important ways. While modern mobile operating systems tend to be more secure than traditional desktop operating systems, problems can still appear if developers don't carefully consider security during mobile app development. These security risks often go beyond the usual concerns with data storage, inter-app communication, proper usage of cryptographic APIs, and secure network communication.

## How to Use the Mobile Application Security Project 

First, the Project recommends that your mobile app security strategies should be based on the [OWASP Mobile Application Security _Verification Standard_ (MASVS)](https://mas.owasp.org/MASVS/), which defines a mobile app security model and lists generic security requirements for mobile apps. MASVS is designed to be used by architects, developers, testers, security professionals, and consumers to define and understand the qualities of a secure mobile app. After you have determined how OWASP MASVS applies to your mobile app's security model, the Project suggests that you use the [OWASP Mobile Application Security _Testing Guide_ (MASTG)](https://mas.owasp.org/MASTG/). The Testing Guide maps to the same basic set of security requirements offered by the MASVS and depending on the context, they can be used individually or combined to achieve different objectives.

<img src="Images/Chapters/0x03/owasp-mobile-overview.png" width="50%" />

For example, the MASVS requirements can be used in an app's planning and architecture design stages while the checklist and testing guide may serve as a baseline for manual security testing or as a template for automated security tests during or after development. In the ["Mobile App Security Testing"](0x04b-Mobile-App-Security-Testing.md) chapter we'll describe how you can apply the checklist and MASTG to a mobile app penetration test.

## What's Covered in the Mobile Testing Guide

Throughout this guide, we will focus on apps for Android and iOS running on smartphones. These platforms are currently dominating the market and also run on other device classes including tablets, smartwatches, smart TVs, automotive infotainment units, and other embedded systems. Even if these additional device classes are out of scope, you can still apply most of the knowledge and testing techniques described in this guide with some deviance depending on the target device.

Given the vast amount of mobile app frameworks available it would be impossible to cover all of them exhaustively. Therefore, we focus on _native_ apps on each operating system. However, the same techniques are also useful when dealing with web or hybrid apps (ultimately, no matter the framework, every app is based on native components).

## Navigating the OWASP MASTG

The MASTG contains descriptions of all requirements specified in the MASVS. The MASTG contains the following main sections:

1. The [General Testing Guide](0x04a-Mobile-App-Taxonomy.md) contains a mobile app security testing methodology and general vulnerability analysis techniques as they apply to mobile app security. It also contains additional technical test cases that are OS-independent, such as authentication and session management, network communications, and cryptography.

2. The [Android Testing Guide](0x05a-Platform-Overview.md) covers mobile security testing for the Android platform, including security basics, security test cases, reverse engineering techniques and prevention, and tampering techniques and prevention.

3. The [iOS Testing Guide](0x06a-Platform-Overview.md) covers mobile security testing for the iOS platform, including an overview of the iOS OS, security testing, reverse engineering techniques and prevention, and tampering techniques and prevention.

## How Security Personnel Should Address Mobile Security Testing

Many mobile app penetration testers have a background in network and web app penetration testing, a quality that is valuable for mobile app testing. Almost every mobile app talks to a backend service, and those services are prone to the same types of attacks we are familiar with in web apps on desktop machines. Mobile apps have a smaller attack surface and therefore have more security against injection and similar attacks. Instead, the MASTG prioritizes data protection on the device and the network to increase mobile security.

## OWASP MASVS Overview: Key Areas in Mobile Application Security

This overview discusses how the MASVS defines and describes the key areas of mobile security:

[Data Storage and Privacy](#datastorage)
[Cryptography](#crypto)
[Authentication and Authorization](#auth)
[Network Communication](#network)
[Interaction with the Mobile Platform](#code)
[Anti-Tampering and Anti-Reversing](#resilience)

### <A id="datastorage"></a> MASVS-STORAGE: Data Storage and Privacy

The Standard is based on the principle that protecting sensitive data, such as user credentials and private information, is crucial to mobile security. If an app does not use operating system APIs properly, especially those that handle local storage or inter-process communication (IPC), the app could expose sensitive data to other apps running on the same device or may unintentionally leak data to cloud storage, backups, or the keyboard cache. And since mobile devices are more likely to be or lost or stolen, attackers can actually gain physical access to the device, which would make it easier to retrieve the data.

Thus we must take extra care to protect stored user data in mobile apps. Some solutions may include appropriate key storage APIs and using hardware-backed security features (when available).

Fragmentation is a problem we deal with especially on Android devices. Not every Android device offers hardware-backed secure storage, and many devices are running outdated versions of Android. For an app to be supported on these out-of-date devices, it would have to be created using an older version of Android's API which may lack important security features. For maximum security, the best choice is to create apps with the current API version even though that excludes some users.

### <A id="crypto"></a> MASVS-CRYPTO: Cryptography

Cryptography is an essential ingredient when it comes to protecting data stored on a mobile device. It is also an area where things can go horribly wrong, especially when standard conventions are not followed. It is essential to ensure that the application uses cryptography according to industry best practices, including the use of proven cryptographic libraries, a proper choice and configuration of cryptographic primitives as well as a suitable random number generator wherever randomness is required.

### <A id="auth"></a>MASVS-AUTH: Authentication and Authorization

In most cases, sending users to log in to a remote service is an integral part of the overall mobile app architecture. Even though most of the authentication and authorization logic happens at the endpoint, there are also some implementation challenges on the mobile app side. Unlike web apps, mobile apps often store long-time session tokens that are unlocked with user-to-device authentication features such as fingerprint scanning. While this allows for a quicker login and better user experience (nobody likes to enter complex passwords), it also introduces additional complexity and room for error.

Mobile app architectures also increasingly incorporate authorization frameworks (such as OAuth2) that delegate authentication to a separate service or outsource the authentication process to an authentication provider. Using OAuth2 allows the client-side authentication logic to be outsourced to other apps on the same device (e.g. the system browser). Security testers must know the advantages and disadvantages of different possible authorization frameworks and architectures.

### <a id="network"></a> MASVS-NETWORK: Network Communication

Mobile devices regularly connect to a variety of networks, including public Wi-Fi networks shared with other (potentially malicious) clients. This creates opportunities for a wide variety of network-based attacks ranging from simple to complicated and old to new. It's crucial to maintain the confidentiality and integrity of information exchanged between the mobile app and remote service endpoints. As a basic requirement, mobile apps must set up a secure, encrypted channel for network communication using the TLS protocol with appropriate settings.

### <a id="platform"></a> MASVS-PLATFORM: Interaction with the Mobile Platform

Mobile operating system architectures differ from classical desktop architectures in important ways. For example, all mobile operating systems implement app permission systems that regulate access to specific APIs. They also offer more (Android) or less rich (iOS) inter-process communication (IPC) facilities that enable apps to exchange signals and data. These platform-specific features come with their own set of pitfalls. For example, if IPC APIs are misused, sensitive data or functionality might be unintentionally exposed to other apps running on the device.

### <a id="code"></a> MASVS-CODE: Code Quality and Exploit Mitigation

Traditional injection and memory management issues aren't often seen in mobile apps due to the smaller attack surface. Mobile apps mostly interact with the trusted backend service and the UI, so even if many buffer overflow vulnerabilities exist in the app, those vulnerabilities usually don't open up any useful attack vectors. The same applies to browser exploits such as cross-site scripting (XSS allows attackers to inject scripts into web pages) that are very prevalent in web apps. However, there are always exceptions. XSS is theoretically possible on mobile in some cases, but it's very rare to see XSS issues that an individual can exploit.

This protection from injection and memory management issues doesn't mean that app developers can get away with writing sloppy code. Following security best practices results in hardened (secure) release builds that are resilient against tampering. Free security features offered by compilers and mobile SDKs help increase security and mitigate attacks.

### <a id="resilience"></a> MASVS-RESILIENCE: Anti-Tampering and Anti-Reversing

There are three things you should never bring up in polite conversations: religion, politics, and code obfuscation. Many security experts dismiss client-side protections outright. However, software protection controls are widely used in the mobile app world, so security testers need ways to deal with these protections. We believe there's a benefit to client-side protections if they are employed with a clear purpose and realistic expectations in mind and aren't used to replace security controls.
