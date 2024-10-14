---
title: User Data Control 
id: MASWE-0112
alias: user-data-control
platform: ["android", "ios"]
profiles: ["P"]
mappings:
  masvs-v1: [MSTG-STORAGE-12]
  masvs-v2: [MASVS-PRIVACY-4]
  cwe: [359]
status: new
---

## Overview

Offering users control over their data refers to giving the user the option of managing, deleting, modifying and revoking access to their data. Including obtaining additional consent when requesting more data than initially specified.

The risk here is the user not having control of their data once collected. To mitigate this risk, users should have the option to request deletion of collected data and revoke consent. Additionally, users should be able to modify their privacy settings with granularity.


## Modes of Introduction

This risk can be introduced in various scenarios, including:

- Not providing the user with the option to delete, modify and opt out of data collection.
- Not providing privacy setting with granularity.
- Not prompting the user for consent if data collection has changed.



## Impact

The impact of users lacking control over their data: 

-**Loss of User Trust**: Users losing trust in the application, leading to reputational damage and potential loss of business.
-**Loss of Control**: Users cannot manage, delete, or modify their data, leaving them vulnerable to potential misuse or unauthorized access.

## Mitigations

To mitigate this risk, consider the following strategies:

- Ensure mechanisms are in place for users to delete all their data and modify privacy settings with granularity.
- Ensure mechanisms for prompting for consent if data collection has changed.
