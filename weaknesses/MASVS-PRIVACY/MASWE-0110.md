---
title: Use of Unique Identifiers for User Tracking
id: MASWE-0110
alias: unique-identifiers-user-tracking
platform: ["android", "ios"]
profiles: ["P"]
mappings:
  masvs-v1: []
  masvs-v2: [MASVS-PRIVACY-2]
  cwe: [359]
refs:
- https://developer.android.com/reference/android/provider/Settings.Secure#ANDROID_ID
- https://developer.android.com/privacy-and-security/about#resettable-identifiers
- https://developer.android.com/identity/user-data-ids
- https://developer.android.com/identity/user-data-ids#common-use-cases
- https://developer.android.com/identity/ad-id
- https://developers.google.com/privacy-sandbox/private-advertising/attribution-reporting/android
- https://developer.apple.com/app-store/app-privacy-details/#user-tracking
- https://developer.apple.com/app-store/user-privacy-and-data-use/
- https://developer.apple.com/documentation/apptrackingtransparency/
- https://developer.apple.com/documentation/adsupport/asidentifiermanager/advertisingidentifier
- https://developer.apple.com/documentation/uikit/uidevice/1620059-identifierforvendor/
- https://developer.apple.com/app-store/ad-attribution/
- https://developer.apple.com/documentation/adattributionkit
- https://gdpr-info.eu/recitals/no-30/

status: new
---

## Overview

User tracking in mobile applications involves collecting and analyzing data to monitor user behavior, preferences, and movements. This enables companies to recognize and follow users over time and across different apps, devices, and services. Such tracking often occurs without the user's explicit knowledge or consent, leading to significant privacy concerns.

Mobile apps commonly include embedded utilities or third-party SDKs from companies like Google, Meta (formerly Facebook), X (formerly Twitter), and others. Examples of these utilities include analytics tools, ad networks, and social media integration components. These components can collect data not directly related to the app's functionality, potentially accessing sensitive information like contact lists or location history, depending on the permissions granted. Pre-installed apps by device manufacturers can further complicate the issue, as they may engage in invasive data collection without users' knowledge.

One common method of tracking is through the use of unique identifiers, especially those that cannot be reset. When combined with data from multiple apps, these identifiers can be used to create detailed profiles of individuals—estimating interests, health status, sexual orientation, and other personal attributes. This information can be utilized for targeted advertising, personalized content delivery, or even to influence political opinions.

## Modes of Introduction

- **Use of Non-Resettable Identifiers**: Utilizing identifiers that cannot be reset by the user, such as device IDs, hardware serial numbers, or MAC addresses, can lead to persistent tracking without user consent. For example, the [ANDROID_ID](https://developer.android.com/reference/android/provider/Settings.Secure#ANDROID_ID) before Android 8.0 (API level 26) was a non-resettable identifier randomly generated at first boot, while in recent versions it's unique to each combination of app-signing key, user, and device.
- **Misuse of Resettable Identifiers**: Using [resettable identifiers](https://developer.android.com/privacy-and-security/about#resettable-identifiers) like the [Advertising ID](https://developer.android.com/identity/user-data-ids#advertising-ids) on Android or [Advertising Identifier (aka. Identifier for Advertiseers or IDFA)](https://developer.apple.com/documentation/adsupport/asidentifiermanager/advertisingidentifier) on iOS without respecting user preferences or obtaining proper consent can lead to unauthorized tracking.
- **Linking Identifiers Across Services**: Linking identifiers across different services or apps to create a unified profile of a user, even after a reset or reinstall. This can be done by combining identifiers from different sources, such as device IDs, advertising IDs, or other unique identifiers as well as behavioral data.
- **Tracking Without User Consent**: Tracking users across services or apps without their explicit consent or without providing the ability to opt out or reset identifiers. For instance, on iOS, access to the IDFA requires explicit user consent under the [App Tracking Transparency (ATT) framework](https://developer.apple.com/documentation/AppTrackingTransparency). The IDFV can track users across apps by the same vendor without explicit consent but resets when all of the vendor's apps are removed from the device.

## Impact

- **Loss of User Trust**: Users are likely to lose trust in an app that lacks transparency in how unique identifiers are used for tracking, which may lead to negative reviews, decreased engagement, and reduced retention rates.
- **Violation of User Privacy**: Users may not be fully aware of the implications when accepting tracking, such as the collection of unique identifiers or usage patterns. In some cases, tracking may be mandatory to use an app, leaving users without a real choice. This can lead to privacy violations, unauthorized use of their information, and an erosion of user control over their data.
- **Compliance and Legal Risks**: Violation of data protection laws and regulations (like GDPR), resulting in legal consequences, fines, and potential non-compliance with platform guidelines, which may lead to app store removal.

## Mitigations

- **Use Resettable Identifiers**: Prefer [resettable identifiers](https://developer.android.com/privacy-and-security/about#resettable-identifiers) like the [Advertising ID](https://developer.android.com/identity/user-data-ids#advertising-ids) on Android or [Advertising Identifier (aka. Identifier for Advertiseers or IDFA)](https://developer.apple.com/documentation/adsupport/asidentifiermanager/advertisingidentifier) on iOS, for purposes like analytics or personalized advertising. Always respect user preferences and consent regarding tracking and data collection. Avoid using hardware-based identifiers like device IDs or MAC addresses.
- **Use App-Scoped Identifiers**: Use app-scoped identifiers to maintain user privacy and prevent cross-service tracking. Examples include [**ANDROID_ID** (on Android 8.0 (API level 26) and higher)](https://developer.android.com/about/versions/oreo/android-8.0-changes#privacy-all), **Firebase Installation IDs (FIDs)**, or privately stored Globally Unique IDs (GUIDs). On iOS, consider using **Identifier for Vendors (IDFV)** to track users across apps by the same vendor and resets when all the vendor's apps are uninstalled.
- **Use Advertising ID Appropriately**: Restrict advertising ID usage to ad-serving and user profiling contexts, respecting user preferences on ad tracking. Avoid linking identifiers after a reset without explicit user consent, ensuring a fresh start. On Android, [use the **Advertising ID** appropriately](https://support.google.com/googleplay/android-developer/answer/9857753#ad-id), and on iOS, comply with **App Tracking Transparency (ATT)** by [requesting user permission](https://developer.apple.com/documentation/apptrackingtransparency/attrackingmanager/requesttrackingauthorization(completionhandler:)) before accessing the **Identifier for Advertisers (IDFA)** and avoid storing it; access [`advertisingIdentifier`](https://developer.apple.com/documentation/adsupport/asidentifiermanager/advertisingidentifier) instead.
- **Use Appropriate APIs**: Use privacy-preserving APIs instead of relying on identifiers. For example, for device verification on Android use **Play Integrity**, and on iOS use **DeviceCheck** (e.g., to identify devices that have taken advantage of a promotional offer or to flag fraudulent devices). For privacy-friendly ad attribution, use [Attribution Reporting API](https://developers.google.com/privacy-sandbox/private-advertising/attribution-reporting/android) on Android, and consider using **AdAttributionKit** or **SKAdNetwork** on iOS.
- **Treat Third-Party SDKs as Your Own Code**: Be aware of any privacy or security policies associated with third-party SDKs integrated into your app, particularly those related to the use of unique identifiers. Ensure third-party SDKs comply with platform guidelines for data collection and user consent, such as Apple's App Tracking Transparency (ATT) and Google's Play Data Safety policies, to avoid misuse of identifiers and ensure transparency.
- **Provide Clear Privacy Information**: Inform users about the collection and use of unique identifiers in your privacy policy, app store listing, and within the app itself. Clearly explain the purpose of tracking and how it benefits the user experience. Provide users with the ability to opt out of tracking or reset identifiers if possible.
