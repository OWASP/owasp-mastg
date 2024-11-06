---
platform: ios
title: Possible Leakage of Sensitive Data via UIPasteboard
id: MASTG-TEST-0x73-1
type: [static]
weakness: MASWE-0053
threat: [user]
---

## Overview

The systemwide general pasteboard can be obtained by the [`generalPasteboard`](https://developer.apple.com/documentation/uikit/uipasteboard/1622106-generalpasteboard "UIPasteboard generalPasteboard") function. The general pasteboard enables easy sharing of information between apps. However, it can also leak sensitive data, since every app and [potentially even other devices](https://developer.apple.com/documentation/uikit/uipasteboard#3671087 "UIPasteboard") can request the contents. Since iOS 16.0 this requires user interaction.

When you are dealing with sensitive data, usage of the general pasteboard should be avoided. This static test case identifies whether the app uses the general pasteboard.

## Steps

1. Extract the package as described in @MASTG-TECH-0058.
2. Perform static analysis as described in @MASTG-TECH-0066 or if the code is not available look for calls to
   `UIPasteboard.generalPasteboard` using @MASTG-TECH-0076.

## Observation

The code or disassembly could contain calls to `UIPasteboard.generalPasteboard`.

## Evaluation

The test fails if there are calls to `UIPasteboard.generalPasteboard` and sensitive data is written into the resulting object with [`addItems`](https://developer.apple.com/documentation/uikit/uipasteboard/1622101-additems "Apple Developer"), [`setItems`](https://developer.apple.com/documentation/uikit/uipasteboard/1829417-setitems "Apple Developer"), [`setData`](https://developer.apple.com/documentation/uikit/uipasteboard/1622075-setdata "Apple Developer") or [`setValue`](https://developer.apple.com/documentation/uikit/uipasteboard/1622079-setvalue "Apple Developer").

The usage of the general systemwide pasteboard should be avoided when dealing with sensitive data. Prefer using a
[custom app pasteboard](https://developer.apple.com/documentation/uikit/uipasteboard/1622087-withuniquename "Apple Developer") instead.
