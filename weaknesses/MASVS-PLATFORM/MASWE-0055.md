---
title: Sensitive Data Leaked via Screenshots or Screen Recording
id: MASWE-0055
alias: data-leak-screenshots
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-STORAGE-9]
  masvs-v2: [MASVS-PLATFORM-3, MASVS-STORAGE-2]
  cwe: [200, 359]

refs:
- https://developer.android.com/about/versions/14/features/screenshot-detection
draft:
  description: no method is used to prevent specific content from being captured (e.g.
    via FLAG_SECURE on Android and Secure Text Entry on iOS)
  topics:
  - Screenshots Not Prevented (e.g. via DETECT_SCREEN_CAPTURE on Android)
  - Screenshots not deleted when backgrounding
  - Auto-Generated Screenshots
status: placeholder

---

## Overview

Mobile platforms allow users and third-party tools to record screens, which can expose sensitive data and increase the risk of data leakage.

## Impact

- **Loss of Confidentiality**: Under certain conditions, an attacker could access sensitive data previously displayed on the screen, potentially compromising confidentiality and enabling further attacks, such as identity theft or account takeover.

## Modes of Introduction

- **Third-party apps with a permission to recording record the screen**: Third-party apps may record the screen while sensitive content is displayed.
- **Third-party apps with a permission to access the whole storage**: Third-party apps may access screenshots saved in storage after they are taken by the user or a tool.
- **External tools may record the screen**: Tools such as [scrcpy](https://github.com/Genymobile/scrcpy) and [QuickTime](https://support.apple.com/guide/quicktime-player/welcome/mac) can record the device's screen via a USB connection.
- **Backgrounding the app**: When an app enters the background state, the system may capture a screenshot of the app's current view to display in the app switcher. These screenshots are stored on the file system and could potentially be accessed or stolen by malicious actors.
