---
platform: ios
title: Pasteboard Contents Not Restricted to Local Device
id: MASTG-TEST-0280
type: [static]
weakness: MASWE-0053
threat: [app]
profiles: [L2]
---

## Overview

This test checks if the app restricts the contents of the general [pasteboard](../../../Document/0x06h-Testing-Platform-Interaction.md/#pasteboard) to the local device by using the `UIPasteboard.setItems(_:options:)` method with the `UIPasteboard.OptionsKey.localOnly` option. If sensitive data is placed in the general pasteboard without this restriction, it can be synced across devices via Universal Clipboard, leading to potential data leaks.

## Steps

1. Run a static analysis scan using @MASTG-TOOL-0073 to detect usage of the [`UIPasteboard.general`](https://developer.apple.com/documentation/uikit/uipasteboard/1622106-generalpasteboard "UIPasteboard generalPasteboard") property.
2. Run a static analysis scan using @MASTG-TOOL-0073 to detect usage of the `UIPasteboard.setItems(_:options:)` method.

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if the app uses the general pasteboard without restricting its contents to the local device. Specifically, ensure that the `UIPasteboard.setItems(_:options:)` method is called with the `UIPasteboard.Options.localOnly` option.
