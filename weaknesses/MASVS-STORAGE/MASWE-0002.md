---
title: Sensitive Data Stored With Insufficient Access Restrictions in Internal Locations
id: MASWE-0002
alias: data-insufficient-access-restrictions-internal
platform: [android]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-STORAGE-2]
  masvs-v2: [MASVS-STORAGE-2]
  mastg-v1: [MASTG-TEST-0052, MASTG-TEST-0001]
  cwe: [CWE-552, CWE-922]
  android: https://developer.android.com/about/versions/nougat/android-7.0-changes#permfilesys
  android-risks:
  - https://developer.android.com/privacy-and-security/risks/file-providers
refs:
- https://developer.android.com/about/versions/nougat/android-7.0-changes#permfilesys
- https://developer.android.com/privacy-and-security/security-tips#internal-storage
draft:
  description: Sensitive data may be stored in internal locations without ensuring
    exclusive app access (e.g. by using the wrong file permissions) and may be accessible
    to other apps.
  topics:
  - File permissions (Android)
  - improperly configured FileProvider (Android)
  - Avoid the deprecated MODE_WORLD_WRITEABLE and MODE_WORLD_READABLE modes for IPC files, see https://developer.android.com/privacy-and-security/security-tips#internal-storage. They don't provide the ability to limit data access to particular applications, and they don't provide any control of data format. If you want to share your data with other app processes, consider using a content provider instead, which offers read and write permissions to other apps and can make dynamic permission grants on a case-by-case basis.
status: draft
---

## Overview

Mobile apps need to store data within their internal storage to provide the offered functionality to their users. Data may be stored for multiple reasons, such as authentication, sharing data with other applications, or permanently saving data. Even though applications are sandboxed and the internal storage is not accessible from other applications, a misconfiguration in permissions or access controls could create a risk of leaking user data.

For example it was possible to set the constants [MODE_WORLD_READABLE](https://developer.android.com/reference/android/content/Context#MODE_WORLD_READABLE) and [MODE_WORLD_WRITEABLE](https://developer.android.com/reference/android/content/Context#MODE_WORLD_WRITEABLE) to files, but they are both deprecated since API level 17 and will now throw a security exception during build time in Android Studio when being used (`java.lang.SecurityException: MODE_WORLD_READABLE no longer supported`).

## Impact

- **Loss of confidentiality**: Sensitive data could be leaked to other applications.
- **Loss of accessibility**: Sensitive date could be deleted or altered.
- **Loss of integrity**:  Another application could tamper the files that hold sensitive data, impacting application behavior and user experience.

## Modes of Introduction

- **Incorrect Permission Assignment**: Making (part of) the  internal storage readable/writable to 3rd party applications.
- **Improper Limitation of a Pathname**: A wrong file configuration or a dynamic file path could lead to data leakage.

## Mitigations

- If you need to share a file with other applications:
    - Use the `FileProvider` class, which uses a `content://` URI to provide secure, temporary access to files.
    - Use the `MediaStore` API for Media files.
    - Share Files via Scoped Storage
    - use absolute path if you have a complete file system to avoid potential error
- Configure the file permissions so that files are only accessible from the internal storage
