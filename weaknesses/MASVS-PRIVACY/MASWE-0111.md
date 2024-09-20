---
title: Transparency about data collection and usage
id: MASWE-0111
alias: transparency-data-collection-usage
platform: ["android", "ios"]
profiles: ["P"]
mappings:
  masvs-v1: [MASVS-STORAGE-12]
  masvs-v2: [MASVS-PRIVACY-3]
  cwe: [359]
status: new
---

## Overview

Transparency about data collection and usage refers to the user’s right to know what data will be collected and how the collected data is being used.

The risk here is data being collected and shared without user awareness (therefore no consent). To mitigate this, clear information about data collection, storage and sharing practices should be provided to the user, including making the user aware of any behavior they might not expect, such as background data collections.


## Modes of Introduction

This risk can be introduced in various scenarios, including:

- Sensor data or local data is collected without explicit user consent.
- Though consent is present the user is not adequately informed about how the data is used or shared (e.g. between the app and third-party SDKs).
- Discrepancy between store declarations, privacy policy and actual behavior.



## Impact

The impact of collection of user data without user consent: 

-**Loss of User Trust**: Users losing trust in the application, leading to reputational damage and potential loss of business.
-**Gain Privileges**: If users are not aware of how their data is being used, they cannot effectively assess the risks involved. This could lead to their data being used for purposes they find objectionable or harmful, such as targeted advertising, discrimination, or even identity theft.


## Mitigations

To mitigate this risk, consider the following strategies:

- Obtain clear and explicit user consent before accessing sensors or local data.
- Ensure sensitive data is not shared with third parties unless necessary and users are informed if it is.
- Ensure data collection behavior is documented and up to date on privacy policy, app store and matches actual app behavior.
