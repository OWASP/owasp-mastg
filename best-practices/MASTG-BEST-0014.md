---
title: Store Data in the Proper App Sandbox Directory
alias: stora-data-in-proper-app-sandbox-directory
id: MASTG-BEST-0014
platform: ios
---

Choose the right location for storing the app's and the user's data. There are two main directories inside App Sandbox:

- "Documents/"
- "Library/

Use **Documents** directory to store user-generated content and **Library** directory for app's internal data. 

## Why is this important?

An app can be configured to make **Documents** directory accessible to the user in the Files app by setting `UIFileSharingEnabled` and `LSSupportsOpeningDocumentsInPlace`. Therefore, storing databases, config files, purchase state in this directory is highly dangerous because:

- a user can tamper with internal app files
- an attacker with a physical access to the device can copy content of `Documents` directory
- other apps can access `Documents` directory of other apps with a [document picker interface](https://developer.apple.com/documentation/uikit/uidocumentpickerviewcontroller)

**Note:**  Storing data in the correct directory doesn't mean it's secure. For L2 profile apps, it's recommended to encrypt the files before storing them, and put the encryption key into the keychain.
