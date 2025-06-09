---
platform: ios
title: Pasteboard Contents Not Cleared After Use
id: MASTG-TEST-0278
type: [static]
weakness: MASWE-0053
threat: [app]
profiles: [L2]
---

## Overview

This test checks if the app clears the contents of the general [pasteboard](../../../Document/0x06h-Testing-Platform-Interaction.md/#pasteboard) when it moves to the background or terminates. If sensitive data is left in the pasteboard, it can be accessed by other apps, leading to potential data leaks.

Apps can clear the contents of the general pasteboard by setting `UIPasteboard.general.items = []` in the appropriate lifecycle methods, such as `applicationDidEnterBackground:` or `applicationWillTerminate:`.

## Steps

1. Run a static analysis scan using @MASTG-TOOL-0073 to detect usage of the [`UIPasteboard.general`](https://developer.apple.com/documentation/uikit/uipasteboard/1622106-generalpasteboard "UIPasteboard generalPasteboard") property.
2. Run a static analysis scan using @MASTG-TOOL-0073 to detect usage of the [`UIPasteboard.setItems`](https://developer.apple.com/documentation/uikit/uipasteboard/setitems(_:options:) "UIPasteboard setItems") method.

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if the app uses the general pasteboard and does not clear its contents when moving to the background or terminating. Specifically, it should be verified that there are calls to `UIPasteboard.setItems` with an empty array (`[]`) in the appropriate lifecycle methods.
