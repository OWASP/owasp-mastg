---
masvs_v1_id:
- MSTG-PLATFORM-2
masvs_v2_id:
- MASVS-CODE-4
platform: android
title: Testing Local Storage for Input Validation
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

For any publicly accessible data storage, any process can override the data. This means that input validation needs to be applied the moment the data is read back again.

> Note: The same is true for private accessible data on a rooted device

## Static analysis

### Using Shared Preferences

When you use the `SharedPreferences.Editor` to read or write int/boolean/long values, you cannot check whether the data is overridden or not. However: it can hardly be used for actual attacks other than chaining the values (e.g. no additional exploits can be packed which will take over the control flow). In the case of a `String` or a `StringSet` you should be careful with how the data is interpreted.
Using reflection based persistence? Check the section on "Testing Object Persistence" for Android to see how it should be validated.
Using the `SharedPreferences.Editor` to store and read certificates or keys? Make sure you have patched your security provider given vulnerabilities such as found in [Bouncy Castle](https://www.cvedetails.com/cve/CVE-2018-1000613/ "Key reading vulnerability due to unsafe reflection").

In all cases, having the content HMACed can help to ensure that no additions and/or changes have been applied.

### Using Other Storage Mechanisms

In case other public storage mechanisms (than the `SharedPreferences.Editor`) are used, the data needs to be validated the moment it is read from the storage mechanism.
