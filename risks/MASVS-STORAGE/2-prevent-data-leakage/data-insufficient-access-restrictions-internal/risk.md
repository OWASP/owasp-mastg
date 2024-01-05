---
title: Sensitive Data Stored With Insufficient Access Restrictions in Internal Locations
platform: ["android"]
profiles: ["L1", "L2"]
mappings:
  - android: https://developer.android.com/about/versions/nougat/android-7.0-changes#permfilesys
context: not ensuring exclusive app access to sensitive data stored in internal locations e.g. by using the wrong file permissions.
---

## Overview

Mobile apps often handle sensitive data, such as user credentials or private information, which must be stored securely to maintain confidentiality. Failing to restrict access to sensitive data stored in internal locations within the app can lead to unauthorized access and data exposure.

## Modes of Introduction

This can typically occur in these different ways:

- **File Permissions:** Sensitive data stored in internal locations within the app should be protected using appropriate file permissions to ensure only the app has access to the data.

## Impact

Storing sensitive data with insufficient access restrictions in internal locations within the app can have severe consequences:

- **Unauthorized Access:** Attackers or unauthorized users can gain access to internal storage or caches, leading to potential data breaches and privacy violations.
- **Data Corruption and Tampering:** Unauthorized users can modify sensitive data, leading to potential data corruption, data tampering, or data injection.
- **Data Loss and Denial of Service:** Unauthorized users can delete sensitive data, leading to potential data loss or denial of service.
- **Data Disclosure:** Unauthorized users can exploit sensitive data, leading to potential data breaches and privacy violations.

## Mitigations

To mitigate the risk of sensitive data being stored with insufficient access restrictions in internal locations, developers should adhere to the following security practices:

- **Use App-specific Directories:** Store sensitive data in app-specific directories, which are created with restrictive permissions by default (e.g. Android's [Scoped Storage](https://developer.android.com/training/data-storage#scoped-storage)).
- **Use the Platform-provided Keystore:** Use the platform-provided keystore (KeyStore on Android) to securely store cryptographic keys or encrypt sensitive data using keys stored in the keystore.
- **Use the Platform-provided Security Libraries:** Use platform-specific security libraries like EncryptedFile/EncryptedSharedPreferences (Android) to ensure data is stored securely.
- **Use the Platform default File Permissions:** Use the default file permissions to restrict access to sensitive data stored in internal locations within the app.
