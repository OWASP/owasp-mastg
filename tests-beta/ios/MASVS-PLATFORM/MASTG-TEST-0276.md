---
platform: ios
title: Use of the iOS General Pasteboard
id: MASTG-TEST-0276
type: [static]
weakness: MASWE-0053
threat: [app]
prerequisites:
- identify-sensitive-data
profiles: [L2]
---

## Overview

This test checks whether the app uses the systemwide general [pasteboard](../../../Document/0x06h-Testing-Platform-Interaction.md/#pasteboard), which is persistent across device restarts and app uninstalls and is accessible by all foreground apps and, in some cases, other devices. Placing sensitive data here may pose a privacy risk.

The test statically analyzes the code for use of the general pasteboard ([`UIPasteboard.general`](https://developer.apple.com/documentation/uikit/uipasteboard/general)) and checks whether sensitive data is written using any of the following methods:

- [`addItems`](https://developer.apple.com/documentation/uikit/uipasteboard/additems(_:))
- [`setItems`](https://developer.apple.com/documentation/uikit/uipasteboard/setitems(_:options:))
- [`setData`](https://developer.apple.com/documentation/uikit/uipasteboard/setdata(_:forpasteboardtype:))
- [`setValue`](https://developer.apple.com/documentation/uikit/uipasteboard/setvalue(_:forpasteboardtype:))

## Steps

1. Run a static analysis scan using @MASTG-TOOL-0073 to detect usage of the general pasteboard.
2. Run a static analysis scan using @MASTG-TOOL-0073 to detect usage of the pasteboard methods which may be handling sensitive data.

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if calls are made to `UIPasteboard.generalPasteboard` and sensitive data is written to it.

Since determining what constitutes sensitive data is context-dependent, it can be difficult to detect statically. To check if sensitive data is being written to the pasteboard using the aforementioned methods, inspect the reported code locations in the reverse-engineered code (see @MASTG-TECH-0076).
