---
platform: android
title: Testing for App Permissions
id: MASTG-TEST-0x24
weakness: MASWE-0116
---

## Overview

Testing for app permissions in Android involves evaluating how an application requests, uses, and manages permissions to ensure they do not lead to security vulnerabilities. Proper permission management should protect sensitive user data and ensure that the application complies with Android's security model. The test aims to detect misconfigurations and unnecessary permissions.

## Steps

There are multiple tools that can help in finding permissions in use by an application. Refer @MASTG-TECH-0118 to and use any of the mentioned tools.

## Observation

The output shows the list of permissions used by the application.

## Evaluation

  Please refer to this [permissions overview](https://developer.android.com/guide/topics/permissions/overview) for descriptions of the listed permissions that are considered dangerous.
