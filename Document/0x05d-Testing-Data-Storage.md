---
masvs_category: MASVS-STORAGE
platform: android
---

# Android Data Storage

## Overview

This chapter discusses the importance of securing sensitive data, like authentication tokens and private information, vital for mobile security. We'll look at Android's APIs for local data storage and share best practices.

While it's preferable to limit sensitive data on local storage, or avoid it at all whenever possible, practical use cases often necessitate user data storage. For example, to improve user experience, apps cache authentication tokens locally, circumventing the need for complex password entry at each app start. Apps may also need to store personally identifiable information (PII) and other sensitive data.

Sensitive data can become vulnerable if improperly protected, potentially stored in various locations, including the device or an external SD card. It's important to identify the information processed by the mobile app and classify what counts as sensitive data. Check out the ["Identifying Sensitive Data"](0x04b-Mobile-App-Security-Testing.md#identifying-sensitive-data "Identifying Sensitive Data") section in the "Mobile App Security Testing" chapter for data classification details. Refer to [Security Tips for Storing Data](https://developer.android.com/training/articles/security-tips.html#StoringData "Security Tips for Storing Data") in the Android developer's guide for comprehensive insights.

Sensitive information disclosure risks include potential information decryption, social engineering attacks (if PII is disclosed), account hijacking (if session information or an authentication token is disclosed), and app exploitation with a payment option.

In addition to data protection, validate and sanitize data from any storage source. This includes checking correct data types and implementing cryptographic controls, such as HMACs, for data integrity.

Android offers various [data storage](https://developer.android.com/training/data-storage "Storing Data in Android") methods, tailored to users, developers, and applications. Common persistent storage techniques include:

- Shared Preferences
- SQLite Databases
- Firebase Databases
- Realm Databases
- Internal Storage
- External Storage
- Keystore

Additionally, other Android functions that can result in data storage and should be tested include:

- Logging Functions
- Android Backups
- Processes Memory
- Keyboard Caches
- Screenshots

Understanding each relevant data storage function is crucial for performing the appropriate test cases. This overview provides a brief outline of these data storage methods and points testers to further relevant documentation.
