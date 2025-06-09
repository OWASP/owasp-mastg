---
platform: ios
title: Pasteboard Contents Not Expiring
id: MASTG-TEST-0279
type: [static]
weakness: MASWE-0053
threat: [app]
profiles: [L2]
---

## Overview

This test checks if the app sets an expiration date for the contents of the general [pasteboard](../../../Document/0x06h-Testing-Platform-Interaction.md/#pasteboard) using the `UIPasteboard.setItems(_:options:)` method with the `UIPasteboard.Options.expirationDate` option. If sensitive data is left in the pasteboard without an expiration date, it can be accessed by other apps indefinitely, leading to potential data leaks.

## Steps

1. Run a static analysis scan using @MASTG-TOOL-0073 to detect usage of the [`UIPasteboard.general`](https://developer.apple.com/documentation/uikit/uipasteboard/1622106-generalpasteboard "UIPasteboard generalPasteboard") property.
2. Run a static analysis scan using @MASTG-TOOL-0073 to detect usage of the `UIPasteboard.setItems(_:options:)` method.

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if the app uses the general pasteboard without setting an expiration date for its contents. Specifically, ensure that the `UIPasteboard.setItems(_:options:)` method is called with the `UIPasteboard.Options.expirationDate` option.
