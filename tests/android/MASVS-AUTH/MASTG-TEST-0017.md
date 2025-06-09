---
masvs_v1_id:
- MSTG-AUTH-1
- MSTG-STORAGE-11
masvs_v2_id:
- MASVS-AUTH-2
platform: android
title: Testing Confirm Credentials
masvs_v1_levels:
- L2
profiles: [L2]
---

## Overview

## Static Analysis

Make sure that the unlocked key is used during the application flow. For example, the key may be used to decrypt local storage or a message received from a remote endpoint. If the application simply checks whether the user has unlocked the key or not, the application may be vulnerable to a local authentication bypass.

## Dynamic Analysis

Validate the duration of time (seconds) for which the key is authorized to be used after the user is successfully authenticated. This is only needed if `setUserAuthenticationRequired` is used.
