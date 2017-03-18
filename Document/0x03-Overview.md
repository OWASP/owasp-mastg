# Introduction to the Mobile Security Testing Guide

Technological revolutions can happen quickly. Less than a decade ago, smartphones were clunky devices with little keyboards - expensive playthings for tech-savvy business users. Today, smartphones are an essential part of our lives. We've come to rely on them for information, navigation and communication, and they are ubiquitous both in business and in our social lives.

Apps running on those devices store our personal information, pictures, recordings, notes, account data, business information, location and much more. They act as clients that connect us to services we use on a daily basis, and as communications hubs that processes each and every message we exchange with others. Compromise a person's smartphone and you get unfiltered access to that person's life. When we consider that mobile devices are more readily lost or stolen and mobile malware is on the rise, the need for data protection becomes even more apparent.

Every new technology introduces new security risks, and mobile computing is no different. Even though modern mobile operating systems like iOS and Android are arguably more secure by design compared to traditional Desktop operating systems, there's still a lot of things that can go wrong when security is not considered during the mobile app development process. Data storage, inter-app communication, proper usage of cryptographic APIs and secure network communication are only some of the aspects that require careful consideration.

## Mobile Application Threats

Security concerns in the mobile app space differ from traditional Desktop software in some important ways. Firstly, while not many people opt to carry a Desktop tower around in their pocket, doing this with a mobile device is decidedly more common. As a consequence, mobile devices are more readily lost and stolen, so adversaries are more likely to get physical access to a device and access any of the data stored.

From the view of a mobile app, this means that extra care has to be taken when storing user data, such as using appropriate key storage APIs and taking advantage of hardware-backed security features when available. Here however we encounter another problem: Much depends on the device and operating system the app is running on, as well as its configuration. Is the keychain locked with a passcode? What if the device doesn't offer hardware-backed secure storage, as is the case with some Android devices? Can and should the app even verify this, or is it the responsibility of the user? 

Another key difference to their more stationary cousins is that mobile devices regularly connect to a variety of networks, including public WiFi networks shared with other (possibly malicious) clients. This creates great opportunities for network-based attacks, from simple packet sniffing to creating a rogue access point and going SSL man-in-the-middle (or even old-school stuff like routing protocol injection - those baddies use whatever works).

-- TODO What is the OWASP Mobile Top 10 --

## Organization of the Testing Guide

-- TODO Describe the organization of the current guide --

## Using the OWASP Mobile Security Testing Guide

This guide belongs to a set of three mobile appsec-related documents produced by OWASP. Those three documents are closely related: They all map to the same basic set of requirements. Depending on the context, they can be used stand-alone or in combination to achieve different objectives:

- The **Mobile Application Security Verification Standard (MASVS)** contains generic security requirements along with mappings to verification levels that can be chosen depending on the overall need for security [1].

- The **Mobile Security Testing Guide (MSTG)** (this document) provides verification instructions for each requirement in the MASVS, as well as security best practices for apps on each supported mobile operating system (currently Android and iOS). It is also useful as a standalone learning resource and reference guide for mobile application security testers.

- The **Mobile App Security Checklist** can be used to apply the MASVS requirements during practical assessments. It also conveniently links to the MSTG test case for each requirement, making mobile penetration testing a breeze.

![Document Overview](Images/Chapters/0x03/owasp-mobile-overview.jpg)

-- TODO Develop the way the 3 guides can be used to provide added value to a project --
