# Mobile App User Privacy Protection

**IMPORTANT DISCLAIMER:** The MSTG is not a legal handbook. Therefore, we will not deep dive into the GDPR or other possibly relevant legislations here. This chapter is meant to introduce you to the topics and provide you with essential references that you can use to continue researching by yourself. We'll also do our best effort to provide you with tests or guidelines for testing the privacy related requirements listed in the OWASP MASVS.

## Overview

### The Main Problem

Mobile apps handle all kinds of sensitive user data, from identification and banking information to health data. There is an understandable concern about how this data is handled and where it ends up. We can also talk about "benefits users get from using the apps" vs "the real price that they are paying for it" (usually and unfortunately without even being aware of it).

### The Solution (pre 2020)

To ensure that users are properly protected, legislation such as the [General Data Protection Regulation (GDPR)](https://gdpr-info.eu/ "GDPR") in Europe has been developed and deployed (applicable since May 25, 2018), forcing developers to be more transparent regarding the handling of sensitive user data. This has been mainly implemented using privacy policies.

### The Challenge

There are two main dimensions to consider here:

- **Developer Compliance**: Developers need to comply with legal privacy principles since they are enforced by law. Developers need to better comprehend the legal principles in order to know what exactly they need to implement to remain compliant. Ideally, at least, the following must be fulfilled:
  - **Privacy-by-Design** approach (Art. 25 GDPR, "Data protection by design and by default").
  - **Principle of Least Privilege** ("Every program and every user of the system should operate using the least set of privileges necessary to complete the job.")
- **User Education**: Users need to be educated about their sensitive data and informed about how to use the application properly (to ensure a secure handling and processing of their information).

> Note: More often than not apps will claim to handle certain data, but in reality that's not the case. The IEEE article ["Engineering Privacy in Smartphone Apps: A Technical Guideline Catalog for App Developers" by Majid Hatamian](https://www.researchgate.net/publication/339349349_Engineering_Privacy_in_Smartphone_Apps_A_Technical_Guideline_Catalog_for_App_Developers) gives a very nice introduction to this topic.

### Protection Goals for Data Protection

When an app needs personal information from a user for its business process, the user needs to be informed on what happens with the data and why the app needs it. If there is a third party doing the actual processing of the data, the app should inform the user about that too.

Surely you're already familiar with the  classic  triad  of  security  protection  goals:  confidentiality,  integrity,  and  availability. However, you might not be aware of the three protection goals that have been proposed to focus on data protection:

- **Unlinkability**:
  - Users' privacy-relevant data must be unlinkable to any other set of privacy-relevant data outside of the domain.
  - Includes: data minimization, anonymization, pseudonymization, etc.
- **Transparency**:
  - Users should be able to request all information that the application has on them, and be explained how to request this information.
  - Includes: privacy policies, user education, proper logging and auditing mechanisms, etc.
- **Intervenability**:
  - Users should be able to correct their personal information, request its deletion and withdraw any given consent at any time, and be explained how to do so.
  - Includes: privacy settings directly in the app, single points of contact for individuals’ intervention requests (e.g. in-app chat, telephone number, e-mail), etc.

> See Section 5.1.1 "Introduction to data protection goals" in ENISA's ["Privacy and data protection in mobile applications"](https%3A%2F%2Fwww.enisa.europa.eu%2Fpublications%2Fprivacy-and-data-protection-in-mobile-applications%2Fat_download%2FfullReport&usg=AOvVaw06m90YDUaLCeeD2r-Ompgn) for more detailed descriptions.

Addressing both security and privacy protection goals at the same time is a very challenging task (if not impossible in many cases). There is an interesting visualization in IEEE's publication [Protection Goals for Privacy Engineering](https://ieeexplore.ieee.org/document/7163220) called ["The Three Axes"](https://ieeexplore.ieee.org/document/7163220#sec2e) representing the impossibility to ensure 100% of each of the six goals simultaneously.

Most parts of the processes derived from the protection goals are traditionally being covered in a privacy policy. However, this approach is not always optimal:

- developers are not legal experts but still need to be compliant.
- users would be required to read usually long and wordy policies.

### The New Approach (Google's and Apple's take on this)

In order to address these challenges and help users easily understand how their data is being collected, handled and shared, Google and Apple introduced new privacy labeling systems (very much along the lines of NIST's proposal for [Consumer Software Cybersecurity Labeling](https://www.nist.gov/system/files/documents/2021/11/01/Draft%20Consumer%20Software%20Labeling.pdf):

- the App Store [Nutrition Labels](https://www.apple.com/privacy/labels/) (since 2020).
- the Google Play [Data Safety Labels](https://android-developers.googleblog.com/2021/05/new-safety-section-in-google-play-will.html) (since 2021).

As a new requirement on both platforms, it's vital that these labels are accurate in order to provide user assurance and mitigate developer abuse.

### Common Violations that Can Be Addressed with the New Approach

This is a non-exhaustive list of common violations that you as as security tester should report:

- An app collects device location but does not have a prominent disclosure explaining which feature uses this data and/or indicates the app's usage in the background.
- An app has a runtime permission requesting access to data before the prominent disclosure which specifies what the data is used for.
- An app that accesses a user's phone or contact book data and doesn't treat this data as personal or sensitive data that is subject to the above Privacy Policy, data handling, and Prominent Disclosure and Consent requirements.
- An app that records a user’s screen and doesn't treat this data as personal or sensitive data that is subject to this policy.

Since we keep talking about location, contacts, screen recordings, etc., you probably have noticed that all of this is closely related to app permissions. App developers must explain to the user why their app needs the permissions it requests. Both [iOS](https://developer.apple.com/design/human-interface-guidelines/ios/app-architecture/requesting-permission/) and [Android](https://developer.android.com/training/permissions/requesting.html#explain) have specific guidelines and best practices for that.

> App Permissions have its own dedicated requirement in the OWASP MASVS, we suggest that you refer to the related test "Testing App Permissions (MSTG-PLATFORM-1)" for [Android](0x05h-Testing-Platform-Interaction.md#testing-app-permissions-mstg-platform-1) and [iOS](0x06h-Testing-Platform-Interaction.md#testing-app-permissions-mstg-platform-1).

### Learn More

You can learn more about this and other privacy related topics here:

- [iOS App Privacy Policy](https://developer.apple.com/documentation/healthkit/protecting_user_privacy#3705073)
- [iOS Privacy Details Section on the App Store](https://developer.apple.com/app-store/app-privacy-details/)
- [iOS Privacy Best Practices](https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy)
- [Android App Privacy Policy](https://support.google.com/googleplay/android-developer/answer/9859455#privacy_policy)
- [Android Data Safety Section on Google Play](https://support.google.com/googleplay/android-developer/answer/10787469)
- [Android Privacy Best Practices](https://developer.android.com/privacy/best-practices)

## Testing User Education (MSTG-STORAGE-12)

### Testing User Education on Data Privacy on the App Marketplace

At this point we're only interested into knowing which privacy related information is being disclosed by the developers and try to evaluate if it seems reasonable (similarly as you'd do when testing for permissions).

> It's possible that the developers are not declaring certain information that is indeed being collected and/or shared, but that's a topic for a different test extending this one here.

### Static Anaylsis

You can follow these steps:

1. Search for the app in the corresponding app marketplace (e.g. Google Play, App Store).
2. Go to the section ["Privacy Details"](https://developer.apple.com/app-store/app-privacy-details/) (App Store) or ["Safety Section"](https://android-developers.googleblog.com/2021/05/new-safety-section-in-google-play-will.html) (Google Play).
3. Verify if there's any infomation available at all.
4. Compare the information available against the actual context of the app. Does everything makes sense?

Store the information you got from the app marketplace as evidence, if possible on a machine readable format that you can later use to verify potential violations of privacy or data protection by the developers (e.g. by comparing it to an exported [Privacy Report](https://developer.apple.com/documentation/network/privacy_management/inspecting_app_activity_data) on iOS or your own measurements).

### Testing User Education on Security Best Practices

Testing this might be especially challenging if you intend to automate it. We recommend to use the app extensively and try to answer the following questions whenever applicable:

- **Fingerprint usage**: when fingerprints are used for authentication providing access to high risk transactions/information,

    _does the app inform the user about the issues there can be when having multiple fingerprints of other people registered to the device as well?_

- **Rooting/Jailbreaking**: when root or jailbreak detection is implemented,

    _does the app inform the user of the fact that certain high-risk actions will carry additional risk due to the jailbroken/rooted status of the device?_

- **Specific credentials**: when a user gets a recovery code, a password or a pin from the application (or sets one),

    _does the app instruct the user to never share this with anyone else and that only the app will request it?_

- **Application distribution**: in case of a high-risk application and in order to prevent users from downloading compromised versions of the application,

    _does the app manufacturer properly communicate the official way of distributing the app (e.g. from Google Play or the App Store)?_

- **Prominent Disclosure**: on any case,

    _does the app display prominent disclosure of data access, collection, use, and sharing? e.g. does the app use the [App Tracking Transparency Framework](https://developer.apple.com/documentation/apptrackingtransparency) to ask for permission on iOS?_

## References

- Open-Source Licenses and Android - <https://www.bignerdranch.com/blog/open-source-licenses-and-android/>
- Software Licenses in Plain English - <https://tldrlegal.com/>
- Apple Human Interface Guidelines - <https://developer.apple.com/design/human-interface-guidelines/ios/app-architecture/requesting-permission/>
- Android App permissions best practices - <https://developer.android.com/training/permissions/requesting.html#explain>

### OWASP MASVS

- MSTG-STORAGE-12: "The app educates the user about the types of personally identifiable information processed, as well as security best practices the user should follow in using the app."
