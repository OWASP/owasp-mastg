---
masvs_v1_id:
- MSTG-PLATFORM-4
masvs_v2_id:
- MASVS-PLATFORM-1
platform: ios
title: Testing UIPasteboard
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
deprecation_note: New version available in MASTG V2
covered_by: [MASTG-TEST-0276, MASTG-TEST-0277, MASTG-TEST-0278, MASTG-TEST-0279, MASTG-TEST-0280]
---

## Overview

## Static Analysis

The **systemwide general pasteboard** can be obtained by using [`generalPasteboard`](https://developer.apple.com/documentation/uikit/uipasteboard/1622106-generalpasteboard?language=objc "UIPasteboard generalPasteboard"), search the source code or the compiled binary for this method. Using the systemwide general pasteboard should be avoided when dealing with sensitive data.

**Custom pasteboards** can be created with [`pasteboardWithName:create:`](https://developer.apple.com/documentation/uikit/uipasteboard/1622074-pasteboardwithname?language=objc "UIPasteboard pasteboardWithName:create:") or [`pasteboardWithUniqueName`](https://developer.apple.com/documentation/uikit/uipasteboard/1622087-pasteboardwithuniquename?language=objc "UIPasteboard pasteboardWithUniqueName"). Verify if custom pasteboards are set to be persistent as this is deprecated since iOS 10. A shared container should be used instead.

In addition, the following can be inspected:

- Check if pasteboards are being removed with [`removePasteboardWithName:`](https://developer.apple.com/documentation/uikit/uipasteboard/1622072-removepasteboardwithname?language=objc "UIPasteboard removePasteboardWithName:"), which invalidates an app pasteboard, freeing up all resources used by it (no effect for the general pasteboard).
- Check if there are excluded pasteboards, there should be a call to `setItems:options:` with the `UIPasteboardOptionLocalOnly` option.
- Check if there are expiring pasteboards, there should be a call to `setItems:options:` with the `UIPasteboardOptionExpirationDate` option.
- Check if the app clears the pasteboard items when going to background or when terminating. This is done by some password manager apps trying to restrict sensitive data exposure.

## Dynamic Analysis

### Detect Pasteboard Usage

Hook or trace the following:

- `generalPasteboard` for the system-wide general pasteboard.
- `pasteboardWithName:create:` and `pasteboardWithUniqueName` for custom pasteboards.

### Detect Persistent Pasteboard Usage

Hook or trace the deprecated [`setPersistent:`](https://developer.apple.com/documentation/uikit/uipasteboard/1622096-setpersistent?language=objc "UIPasteboard setPersistent:") method and verify if it's being called.

### Monitoring and Inspecting Pasteboard Items

To monitor and inspect pasteboard items at runtime you can follow the instructions from @MASTG-TECH-0134.
