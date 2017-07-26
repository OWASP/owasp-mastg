> some comments are in blocks like this, some are in italics within paragraphs. In-line italics are marked with a "Q-" so you can search for those instances  
> to do a technical review of my edits, track changes within git or paste the past version and this version of the doc into a diffchecker such as https://www.diffchecker.com/

# Introduction to the OWASP Mobile Security Testing Guide

The OWASP Mobile Security Testing Guide (MSTG) is an extension of the OWASP Testing Project that performs security testing of Android and iOS mobile devices.

The goal of this project is to help people understand everything they need to know about testing Android and iOS applications. MSTG delivers a complete suite of test cases designed to address the OWASP Mobile Top 10 security risks, the Mobile App Security Checklist, and the Mobile Application Security Verification Standard (MASVS).

>Do we want to give links to those 3 resources/standards mentioned above (if these links exist)? Do we want to link to the OWASP Testing Project? May also want to link the first instance of OWASP to the main site? Are we avoiding links? What are the ways/forms this book is being published?*

## Why Do We Need a Mobile Application Security Testing Guide?

New technology always introduces new security risks, and mobile computing is no exception. Security concerns for mobile apps differ from traditional desktop software in some important ways, including portability and novelty. Modern mobile operating systems are arguably more secure than traditional desktop operating systems, but problems can still appear when we don't carefully consider security during mobile app development. Data storage, inter-app communication, proper usage of cryptographic APIs, and secure network communication are only some of these considerations. 

>The second paragraph that used to be here is kinda repeated below in Local Data Storage, so I removed the duplicate content and just hinted at it, keeping the explanation down below. 

## Key Areas in Mobile Application Security (AppSec)

Many mobile application penetration testing tools have a background in network and web app penetration (app pen) testing, a quality that is valuable for mobile app testing. Almost every mobile app talks to a backend service, and those services are prone to the same kinds of attacks we are familiar with in web apps on desktop machines. Mobile apps differ in that there is a smaller attack surface and therefore more security against injection (attackers supply input to a program) and similar attacks. Instead, we must prioritize data protection on the device and the network to increase mobile security. 

Let's discuss the key areas in mobile application security.

>Maybe it's a good idea to number each security area below to keep it tied into this introductory sentence above? Maybe not, let me know your thoughts.

### Local Data Storage

The protection of sensitive data (such as user credentials and private information) is crucial to mobile security. If operating system mechanisms (such as inter-process communication) are used improperly, sensitive data can be exposed to other apps running on the same device. Data may also unintentionally leak to cloud storage, backups, or the keyboard cache. Additionally, mobile devices can be lost or stolen more easily compared to other types of devices, so it's more likely an individual can gain physical access to sensitive data.

When developing mobile apps, we must take extra care when storing user data. For example, we can use appropriate key storage APIs and take advantage of hardware-backed security features when available.

Fragmentation is a problem we deal with especially on Android devices. Not every Android device offers hardware-backed secure storage, and many devices are running outdated versions of Android. For an app to be supported on these out-of-date devices, it would have to be created using an older version of Android's API which may lack important security features. For maximum security, the best choice is to create apps with the current API version even though that excludes some users.

### Communication with Trusted Endpoints

Mobile devices regularly connect to a variety of networks, including public WiFi networks shared with other (possibly malicious) clients. This creates opportunities for network-based attacks that could be anything from simple packet sniffing (monitoring data passed over a network), to creating a rogue access point and an SSL man-in-the-middle attack (MITM eavesdrops on and alters communication between two parties), or even routing protocol injection. The bad guys aren't picky. For more information about MITM, see **Performing Man-in-the-Middle Attacks on the Network Layer** in the **Testing Network Communication** chapter.

It's crucial to maintain the confidentiality and integrity of information exchanged between the mobile app and remote service endpoints. At the very least, a mobile app must set up a secure, encrypted channel for network communication using the TLS protocol with appropriate settings.

### Authentication and Authorization

In most cases, sending users to log in to a remote service is an integral part of the overall mobile app architecture. Even though most of the authentication and authorization logic happens at the endpoint, there are also some implementation challenges on the mobile app side. Unlike web applications, mobile apps often store long-time session tokens that are unlocked with user-to-device authentication features such as fingerprint scanning. While this allows for a quicker login and better user experience (nobody likes to enter complex passwords), it also introduces additional complexity and room for error.

Mobile app architectures also increasingly incorporate authorization frameworks, such as OAuth2, which delegate authentication to a separate service or outsource the authentication process to an authentication provider. *(Q- Correct? or is everything after "which" only about OAuth2?)* Using OAuth2 allows the client-side authentication logic to be outsourced to other apps on the same device (e.g. the system browser). Security testers must know the advantages and disadvantages of different possible architectures.

### Interaction with the Mobile Platform

Mobile operating system architectures differ from classical desktop architectures in important ways. For example, all mobile operating systems implement app permission systems that regulate access to specific APIs. They also offer more (Android) or less rich (iOS) inter-process communication (IPC) facilities that enable apps to exchange signals and data. These platform-specific features come with their own set of pitfalls. For example, if IPC APIs are misused, sensitive data or functionality might be unintentionally exposed to other apps running on the device.

### Code Quality and Exploit Mitigation

Traditional injection and memory management issues aren't often seen in mobile applications due to the smaller attack surface. Mobile apps mostly interface with the trusted backend service and the UI, so even if many buffer overflow vulnerabilities exist in the app, those vulnerabilities usually don't open up any useful attack vectors. Similar protection exists against browser exploits such as cross-site scripting (XSS allows attackers to inject scripts into webpages to bypass access controls) that are very prevalent in web apps. However, there are always exceptions. XSS is theoretically possible on mobile in some cases, but it's very rare to see XSS issues that an individual can exploit. For more information about XSS, see **Testing for Cross-Site Scripting Flaws** in the **Testing Code Quality** chapter.

>Asking again about links vs just verbal references. Will be nice to replace this with chapter numbers one day too if links should be avoided (ie for a print medium)

This protection from injection and memory management issues doesn't mean that app developers can get away with writing sloppy code. Following security best practices results in hardened (secure) release builds that are resilient against tampering. Free security features offered by compilers and mobile SDKs help increase security and mitigate attacks.

### Anti-Tampering and Anti-Reversing

There are three things you should never bring up in polite conversations: religion, politics, and code obfuscation. Many security experts dismiss client-side protections outright. However, software protection controls are widely used in the mobile app world, so security testers need ways to deal with these protections. We believe there's a benefit to client-side protections if they are employed with a clear purpose and realistic expectations in mind and aren't used to replace security controls.

## The OWASP Mobile AppSec Verification Standard, Checklist, and Testing Guide

This guide belongs to a set of three closely related mobile application security documents. All three documents map to the same basic set of security requirements. Depending on the context, they can be used individually or combined to achieve different objectives:

- The **Mobile Application Security Verification Standard (MASVS):** A standard that defines a mobile application security model and lists generic security requirements for mobile apps. It can be used by architects, developers, testers, security professionals, and consumers to define what a secure mobile application is.

- The **Mobile Security Testing Guide (MSTG):** A manual for testing the security of mobile applications. It provides verification instructions for MASVS requirements and operating system-specific best practices (currently for Android and iOS). The MSTG helps ensure completeness and consistency of mobile app security testing. It can also be a standalone learning resource and reference guide for mobile application security testers.

- The **Mobile App Security Checklist:** A checklist for tracking compliance against the MASVS during practical assessments. We simplify mobile app penetration testing by linking each requirement in the checklist to the corresponding MSTG test case.

![Document Overview](Images/Chapters/0x03/owasp-mobile-overview.jpg)

For example, the MASVS requirements could be used in an app's planning and architecture design stages while the checklist and testing guide may serve as a baseline for manual security testing or as a template for automated security tests during or after development. In the next chapter *(Q- what chapter? let's name it)*, we'll describe how you can apply the checklist and MSTG to a mobile application penetration test.

## Navigating the Mobile Security Testing Guide 

The MSTG contains descriptions of all requirements specified in the MASVS. The MSTG contains the following main sections:

1. The **General Testing Guide** (*Q- "chapters x? to y?"*) contains mobile app security testing methodology and general vulnerability analysis techniques as they apply to mobile application security.

2. The **Android Testing Guide** covers mobile security testing for the Android platform, including security basics, security test cases, reverse engineering techniques and preventions, and tampering techniques and preventions.

3. The **iOS Testing Guide** covers mobile security testing for the iOS platform, including an overview of the iOS OS, security testing, reverse engineering, and anti-reversing.

4. The **Appendix** contains additional technical test cases that are OS-independent, such as authentication and session management, network communications, and cryptography. We also include a methodology for assessing software protection schemes.
