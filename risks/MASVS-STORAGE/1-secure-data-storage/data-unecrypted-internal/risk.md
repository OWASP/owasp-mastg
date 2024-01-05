---
title: Sensitive Data Stored Unencrypted in Internal Locations
platform: ["android", "ios"]
profiles: ["L2"]
---

## Overview

Mobile apps often handle sensitive data, such as user credentials or private information, which must be stored securely to maintain confidentiality. Failing to encrypt sensitive data when stored in internal locations within the app can lead to unauthorized access and data exposure.

## Modes of Introduction

Sensitive data can be stored unencrypted in internal locations within the app, leading to potential security risks. Some common scenarios and areas of concern include:

- **Envelope Encryption (DEK+KEK) or Equivalent:** Apps should utilize envelope encryption mechanisms to protect sensitive data, ensuring it is encrypted using both a Data Encryption Key (DEK) and a Key Encryption Key (KEK).

- **Android Security Library Usage (EncryptedFile/EncryptedSharedPreferences) (Android):** Android provides security libraries like EncryptedFile and EncryptedSharedPreferences to ensure data is stored securely. Failure to use these libraries can result in unencrypted data storage.

- **iOS KeyChain Data Protection Classes (iOS):** iOS apps should make use of the KeyChain Data Protection classes to protect sensitive data. Failure to apply appropriate data protection attributes can lead to unencrypted data storage.

- **Avoiding Data Encoding:** Sensitive data should not be encoded (e.g., using base64 or simple bit operations such as XOR or bit flipping) as an alternative to proper encryption. Such encoding methods do not provide the same level of security.

## Impact

Storing sensitive data unencrypted in internal locations within the app can have severe consequences:

- **Unauthorized Access:** Attackers or unauthorized users with access to internal storage or caches can easily access and exploit sensitive data, potentially leading to data breaches and privacy violations.

## Mitigations

To mitigate the risk of sensitive data being stored unencrypted in internal locations, developers should adhere to the following security practices:

- **Use Encryption at Rest:** Implement strong encryption mechanisms such as envelope encryption (DEK+KEK) or equivalent encryption methods based on platform-specific best practices.

- **Leverage Platform Libraries:** Utilize platform-specific security libraries like EncryptedFile/EncryptedSharedPreferences (Android) and iOS KeyChain Data Protection classes (iOS) to ensure data is stored securely.

- **Use the Platform-provided Keystore:** Use the platform-provided keystore (KeyStore on Android and KeyChain on iOS) to securely store cryptographic keys or encrypt sensitive data using keys stored in the keystore.
