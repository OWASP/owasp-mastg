---
platform: ios
title: Pasteboard Contents Not Restricted to Local Device
id: MASTG-TEST-0280
type: [dynamic]
weakness: MASWE-0053
threat: [app]
status: draft
note: This test checks if the app restricts the contents of the general pasteboard to the local device by using the `UIPasteboard.setItems(_:options:)` method with the `UIPasteboard.OptionsKey.localOnly` option.
---
