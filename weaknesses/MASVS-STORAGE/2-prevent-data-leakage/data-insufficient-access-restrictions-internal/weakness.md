---
title: Sensitive Data Stored With Insufficient Access Restrictions in Internal Locations
alias: data-insufficient-access-restrictions-internal
platform: [android]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-STORAGE-2]
  masvs-v2: [MASVS-STORAGE-2]
  mastg-v1: [MASTG-TEST-0052, MASTG-TEST-0001]
  cwe: [CWE-552, CWE-922]
  android: https://developer.android.com/about/versions/nougat/android-7.0-changes#permfilesys

---

## Overview

Mobile applications often need to store data within their local storage to provide users the best User experience. Data may be stored for multiple reasons, such as authentication, sharing data with other applications, or permanently saving data.
Even though applications are sandboxed and the internal storage is not accessible from other applications, a misconfiguration in permissions or access controls could create a risk of leaking user data.

## Impact
* **Loss of confidentiality**: sensitive data could be leaked to other applications
* **Loss of accessibility**: sensitive date could be deleted or altered
* **Modification of Data and behaviour**:  Another application could tamper with the files that hold sensitive data, impacting application behavior and user experience.

## Modes of Introduction

* **Incorrect Permission Assignment**: Making part of the  local storage readable/writable from external applications outside the internal storage
* **Improper Limitation of a Pathname**: a wrong file configuration or a dynamic file path could lead to data leak

## Mitigations

* Do not make your local storage world readable/writable
* Configure the file permissions so that files are only accessible from the internal storage
* If you need to share the file with other applications:
    * Limit access of the files stored internally to trusted applications
    * Do not share all you internal storage. Configure you file permissions so that you only share some folders or files.
    * use absolute path if you have a complete file system to avoid potential error
