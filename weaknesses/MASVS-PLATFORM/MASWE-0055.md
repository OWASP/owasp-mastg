---
title: Sensitive Data Leaked via Screenshots or Screen Recording
id: MASWE-0055
alias: data-leak-screenshots
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-STORAGE-9]
  masvs-v2: [MASVS-PLATFORM-3, MASVS-STORAGE-2]

refs:
- https://developer.android.com/about/versions/14/features/screenshot-detection
- https://developer.apple.com/documentation/uikit/uiscreen/2921651-iscaptured
- https://developer.apple.com/documentation/uikit/uitraitcollection/scenecapturestate
status: draft

---

## Overview

Mobile platforms allow users and third-party tools to record screens, which can expose sensitive data and increase the risk of data leakage.

## Impact

- **Loss of Confidentiality**: Under certain conditions, an attacker could access sensitive data previously displayed on the screen, potentially compromising confidentiality and enabling further attacks, such as identity theft or account takeover.

## Modes of Introduction

- **Third-party apps with a permission to recording record the screen**: Third-party apps may record the screen while sensitive content is displayed.
- **Third-party apps with a permission to access the whole storage**: Third-party apps may access screenshots saved in storage after they are taken by the user or a tool.
- **External tools may record the screen**: Tools such as [scrcpy](https://github.com/Genymobile/scrcpy) and [QuickTime](https://support.apple.com/guide/quicktime-player/welcome/mac) can record the device's screen via a USB connection.
