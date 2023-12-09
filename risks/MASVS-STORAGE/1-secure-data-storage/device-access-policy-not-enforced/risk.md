---
mappings:
  - owasp-masvs: [MASVS-STORAGE-1]
title: Device Access Security Policy Not Enforced
platform: ["android"]
profiles: ["L2"]
---

## Overview

Mobile apps often rely on device-level security policies to protect user data and ensure the overall security of the app. These policies can include enforcing the use of device passcodes, biometrics, or other security measures to access sensitive app functionality or data.

## Modes of Introduction

The risk of not enforcing device access security policies can occur when developers fail to utilize platform-specific APIs for setting and enforcing these policies. Some examples of platform-specific APIs include:

- On Android, developers can use the `KeyguardManager.isDeviceSecure()` method to check if the device is secured with a PIN, pattern or password.
    - owncloud
        - sample: https://play.google.com/store/apps/details?id=com.owncloud.android
        - source: https://github.com/owncloud/android/blob/master/owncloudApp/src/main/java/com/owncloud/android/presentation/security/SecurityUtils.kt#L74

- On iOS, developers can use the `LAContext.canEvaluatePolicy()` method to evaluate whether biometric authentication (e.g., Touch ID or Face ID) or a passcode is set.
    - firefox
        - sample: https://apps.apple.com/app/firefox-web-browser/id989804926
        - source: https://github.com/mozilla-mobile/firefox-ios/blob/main/Client/Frontend/AuthenticationManager/AppAuthenticator.swift#L52
    - AlphaWallet
        - sample: https://itunes.apple.com/us/app/alphawallet/id1358230430?ls=1&mt=8
        - https://github.com/AlphaWallet/alpha-wallet-ios/blob/master/AlphaWallet/Lock/ViewModels/LockEnterPasscodeViewModel.swift#L13

## Impact

The failure to enforce device access security policies can have several adverse impacts:

- **Unauthorized Access:** Without proper enforcement, unauthorized users may gain access to sensitive app functionality or data, compromising user privacy and security.
- **Data Breaches:** Sensitive user data stored within the app may be at risk of unauthorized access, potentially leading to data breaches and legal consequences.

## Mitigations

To mitigate the risk of not enforcing device access security policies, developers should:

- **Implement Device Access Checks:** Developers must integrate platform-specific APIs (e.g., `isDeviceSecure()` on Android or `LAContext.canEvaluatePolicy()` on iOS) to assess and enforce device access security policies.
- **Appropriate Error Handling:** Implement proper error handling and security mechanisms to respond to failed access policy checks, ensuring that sensitive functionality or data is protected.
- **Security Audits:** Regularly conduct security audits to review and validate the enforcement of device access security policies within the app.
- **User Education:** Educate users on the importance of setting up and maintaining device security measures, such as passcodes or biometric authentication.
