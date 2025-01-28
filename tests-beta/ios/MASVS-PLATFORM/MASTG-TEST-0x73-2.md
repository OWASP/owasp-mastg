---
platform: ios
title: Leakage of Sensitive Data via UIPasteboard
id: MASTG-TEST-0x73-2
type: [dynamic]
weakness: MASWE-0053
threat: [user]
---

## Overview

The systemwide general pasteboard can be obtained by the [`generalPasteboard`](https://developer.apple.com/documentation/uikit/uipasteboard/1622106-generalpasteboard "UIPasteboard generalPasteboard") function. The general pasteboard enables easy sharing of information between apps. However, it can also leak sensitive data, since every app and [potentially even other devices](https://developer.apple.com/documentation/uikit/uipasteboard#3671087 "UIPasteboard") can request the contents. Since iOS 16.0 this requires user interaction.

When you are dealing with sensitive data, usage of the general pasteboard should be avoided. This dynamic test case identifies not only whether the app uses the general pasteboard but also if sensitive data is passed into it.

## Steps

1. Apply @MASTG-TECH-0067 or @MASTG-TECH-0079 to trace calls to [`addItems`](https://developer.apple.com/documentation/uikit/uipasteboard/1622101-additems "Apple Developer"), [`setItems`](https://developer.apple.com/documentation/uikit/uipasteboard/1829417-setitems "Apple Developer"), [`setData`](https://developer.apple.com/documentation/uikit/uipasteboard/1622075-setdata "Apple Developer") or [`setValue`](https://developer.apple.com/documentation/uikit/uipasteboard/1622079-setvalue "Apple Developer") on objects obtained from calling [`generalPasteboard`](https://developer.apple.com/documentation/uikit/uipasteboard/1622106-generalpasteboard "Apple Developer").

## Evaluation

The test fails if sensitive data (possibly entered during dynamic analysis) is traced during a write operation.

The usage of the general systemwide pasteboard should be avoided when dealing with sensitive data. Prefer using a
[custom app pasteboard](https://developer.apple.com/documentation/uikit/uipasteboard/1622087-withuniquename "Apple Developer") instead.
