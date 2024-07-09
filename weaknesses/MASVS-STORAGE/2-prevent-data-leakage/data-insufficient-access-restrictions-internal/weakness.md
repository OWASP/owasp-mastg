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

Often mobile applications needs to store data in files within their private storage. One might want to store data for multiple reasons such as sharing data with other applications or permanently save data.
Even though application are sandboxed and the internal storage is not accessible from other applications a misconfigutaion of the file permission could create a risk to leak user's data.

## Impact
* **Loss of confidentiality**: sensitive data could be leaked to other applications
* **Loss of accessibility**: sensitive date could be deleted or altered
* **Modification of Data and behaviour**: Another application could tamper the file that hold that data which could have an impact on the application behaviour and the user experience

## Modes of Introduction

* **Incorrect Permission Assignment**: Making files readable/writable for applications outside the internal storage
* **Improper Limitation of a Pathname**: a wrong file configuration or a dynamic file path could lead to data leak

## Mitigations

* Do not make files in local storage world readable/writable
* Configure the file permissions so that files are only accessible from the internal storage
* If you need to share the file with other applications:
    * Limit the  access of the files stored internally to trusted applications
    * Do not share all you internal storage. Configure you file permissions so that you only share some folders or files.
    * use absolute path if you have a complete file system to avoid potential error
