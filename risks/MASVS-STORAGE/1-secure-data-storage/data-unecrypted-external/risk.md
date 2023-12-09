---
title: Sensitive Data Stored Unencrypted in External Locations
platform: ["android", "ios"]
profiles: ["L1", "L2"]
mappings:
  - owasp-masvs: [MASVS-STORAGE-1]
---

## Overview

Mobile apps may inadvertently store sensitive data in external locations without proper encryption. External locations include external storage, public folders (e.g., SD card, Photos, Downloads, Caches), external caches, and in the KeyChain (iOS only). Unencrypted sensitive data in external locations can be accessed by other apps and users, potentially leading to data breaches and privacy violations.

## Modes of Introduction

Sensitive data can be stored unencrypted in various external locations within the app, posing security risks. Some common scenarios and areas of concern include:

- **In Scoped Storage (External Storage, Android):** On Android, scoped storage is the recommended way to access external storage, but sensitive data should still be encrypted when stored there.

- **In External Storage (Public Folders, e.g., SD card, Photos, Downloads, Caches, etc.):** Data stored in publicly accessible folders on the device, such as Downloads or Photos, can be accessed by other apps and users if not properly protected.

- **In External Caches:** Caches on external storage may contain unencrypted sensitive data, which can be accessed and exploited.

- **In the KeyChain (iOS Only):** On iOS, sensitive data should be stored in the KeyChain, but failure to do so may result in unencrypted storage.

- **In App-Crafted Backups:** Sensitive data included in app-crafted backups can be exposed if not properly secured.

## Impact

Storing sensitive data unencrypted in external locations can have severe security implications:

- **Unauthorized Access:** Attackers or unauthorized users with access to external storage or caches can access all sensitive data, potentially leading to data breaches and privacy violations if the data is not properly encrypted.

## Mitigations

To mitigate the risk of sensitive data being stored unencrypted in external locations, developers should adopt the following security practices:

- **Use Encryption at Rest:** Implement strong encryption mechanisms to protect sensitive data when stored in external locations. Utilize platform-specific encryption APIs and libraries.

- **Use Scoped Storage (Android):** When storing data in external storage on Android, follow scoped storage guidelines and ensure proper encryption is applied.

- **Use the Platform-provided Keystore:** Use the platform-provided keystore (KeyStore on Android and KeyChain on iOS) to securely store cryptographic keys or encrypt sensitive data using keys stored in the keystore.
