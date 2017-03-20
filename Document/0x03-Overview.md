# Introduction to the Mobile Security Testing Guide

Technological revolutions can happen quickly. Less than a decade ago, smartphones were clunky devices with little keyboards - expensive playthings for tech-savvy business users. Today, smartphones are an essential part of our lives. We've come to rely on them for information, navigation and communication, and they are ubiquitous both in business and in our social lives.

Apps running on those devices store our personal information, pictures, recordings, notes, account data, business information, location and much more. They act as clients that connect us to services we use on a daily basis, and as communications hubs that processes each and every message we exchange with others. Compromise a person's smartphone and you get unfiltered access to that person's life. When we consider that mobile devices are more readily lost or stolen and mobile malware is on the rise, the need for data protection becomes even more apparent.

Every new technology introduces new security risks, and mobile computing is no different. Even though modern mobile operating systems like iOS and Android are arguably more secure by design compared to traditional Desktop operating systems, there's still a lot of things that can go wrong when security is not considered during the mobile app development process. Data storage, inter-app communication, proper usage of cryptographic APIs and secure network communication are only some of the aspects that require careful consideration.

## Mobile Application Threats

Security concerns in the mobile app space differ from traditional desktop software in some important ways. Firstly, while not many people opt to carry a desktop tower around in their pocket, doing this with a mobile device is decidedly more common. As a consequence, mobile devices are more readily lost and stolen, so adversaries are more likely to get physical access to a device and access any of the data stored. Also leaving a device unattended, which allows adversaries temporary physical access (Evil-Maid attack) can already lead to full compromise of the device or steal data without the owner noticing it.

From the view of a mobile app, this means that extra care has to be taken when storing user data, such as using appropriate key storage APIs and taking advantage of hardware-backed security features when available. Here however we encounter another problem: Much depends on the device and operating system the app is running on, as well as its configuration. Is the keychain locked with a passcode? What if the device doesn't offer hardware-backed secure storage, as is the case with some Android devices? Can and should the app even verify this, or is it the responsibility of the user?

Another key difference to their more stationary cousins is that mobile devices regularly connect to a variety of networks, including public WiFi networks shared with other (possibly malicious) clients. This creates great opportunities for network-based attacks, from simple packet sniffing to creating a rogue access point and going SSL man-in-the-middle (or even old-school stuff like routing protocol injection - those baddies use whatever works).

-- TODO [What is the OWASP Mobile Top 10] --

## Organization of the Testing Guide

-- TODO [Describe the organization of the current guide] --

## Using the OWASP Mobile Security Testing Guide

The project develops three documents that can be used to plan and verify security controls during any phase of mobile app development, as well as during pre-release code review and penetration testing:

This guide belongs to a set of three mobile application security related documents. Those three documents are closely related: They all map to the same basic set of requirements. Depending on the context, they can be used stand-alone or in combination to achieve different objectives:

* The **Mobile Application Security Verification Standard (MASVS):** This standard document defines a mobile app security model and lists generic security requirements for mobile apps. It can be used by architects, developers, testers, security professionals, and consumers to define what a secure mobile application is.
* The **Mobile Security Testing Guide (MSTG):** The MSTG (this document) is a manual for testing the security of mobile apps. It provides verification instructions for the requirements in the MASVS along with operating-system-specific best practices (currently for Android and iOS). The MSTG helps ensure completeness and consistency of mobile app security test. It is also useful as a standalone learning resource and reference guide for mobile application security testers.
* The **Mobile App Security Checklist:** A checklist for tracking compliance against the MASVS during practical assessments. The list conveniently links to the MSTG test case for each requirement, making mobile penetration app testing a breeze.

It is important to note that the security standard, testing guide and checklist are closely related: They all map to the same basic set of requirements. Depending on the context, the documents can be used stand-alone or in combination to achieve different objectives.

![Document Overview](Images/Chapters/0x03/owasp-mobile-overview.jpg)

For example, the MASVS requirements may be used in the planning and architecture design stages, while the checklist and testing guide may serve as a baseline for manual security testing or as a template for automated security tests.

The following section will show how to use the checklist to ensure completeness during a mobile application security assessment.

### Preparation

First of all, it needs to be decided what security level of the MASVS to test against. The level of security needed is something that should ideally have been decided at the beginning of the SDLC - but unfortunately we're not living in an ideal world! At the very least, it is a good idea to walk through the checklist and make a reasonable selection of Level 2 (L2) controls to cover during the test - for example if the app handles highly sensitive data.

The controls in MASVS Level 1 (L1) are appropriate for all mobile apps - the rest depends on the threat model and risk assessment for the particular app. Discuss with the app stakeholders what requirements are applicable and which ones are out of scope for testing, perhaps due to business decisions or company policies. Also consider whether some L2 requirements may be needed due to industry regulations or local laws - for example, 2-factor-authentation (2FA) may be obligatory for a financial app.

If security requirements were already defined during the SDLC, even better! Ask for this information and document it on the front page of the Excel sheet ("dashboard"). More guidance on the verification levels and guidance on the certification can be found in the MASVS.

![Preparation](Images/Chapters/0x03/mstg-preparation.png)

All involved parties need to agree on the decisions made and on the scope in the checklist, as this will present the basis for all security testing, regardless if done manually or automatically.

### Mobile App Security Testing

During a manual test you can simply walk through the applicable requirements one-by-one - for a detailed testing how-to simply click on the link in the "Test procedures" column. These links lead to the respective chapter in the OWASP Mobile Security Testing Guide. Note however that work on the guide is still ongoing so some how-tos have not been written yet (ideally, if you discover missing content, you could contribute it yourself).

![The checklist. Requiremenets marked with "L1" should alwasy be verified. Choose either "Pass" or "Fail" in the "Status" column. The links in the "Testing Procedure" column lead to the OWASP Mobile Secuiryt Testing Guide.](Images/Chapters/0x03/mstg-test-cases.png)

The status column can have three different values that need to be filled out:

* **Pass:** Requirement is applicable to mobile App and implemented according to best practices.
* **Fail:** Requirement is applicable to mobile App but not fulfilled.
* **N/A:** Requirement is not applicable to mobile App.

### Reverse Engineering Resiliency Testing

*Resiliency Testing* is a new concept introduced in the OWASP MSTG. This kind of testing is used if the app implements defenses against client-side threats, such as tampering and extracting sensitive information. As we  know, such protection is never 100% effective. The goal in resiliency testing is to verify that no glaring weaknesses exist in the protection scheme, and that the expectations as to its effectiveness are met (e.g., a skilled reverse engineer should be forced to invest significant effort to do reach a particular goal).

### The Management Summary

A spider chart is generated on the fly according to the results of the requirements for both supported platforms (Android and iOS) in the "Management Summary" tab. You can use this in your report to point out areas that need improvement, and visualize progress over time.

![Management Summary - Spider Chart](Images/Chapters/0x03/mstg-spiderchart.png)

The spider chart visualizes the ratio of passed and failed requirements in each domain. As can be seen above all requirements in "V3: Cryptography Verification Requirements" were set to "pass", resulting in a value of 1.00. Requirements that are set to N/A are not included in this chart.

A more detailed overview can also be found in the "Management Summary" tab. This table gives an overview according to the eight domains and breaks down the requirements according to it's status (Passed, Failed or N/A). The percentage column is the ratio from passed to failed requirements and is the input for the spider chart described above.

![Management Summary - Detailed Overview](Images/Chapters/0x03/mstg-detailed-summary.png)


-- TODO [Develop the way the 3 guides can be used to provide added value to a project] --
