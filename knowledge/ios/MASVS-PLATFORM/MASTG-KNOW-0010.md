---
masvs_category: MASVS-PLATFORM
platform: ios
title: Pasteboard
---

Using the [`UIPasteboard`](https://developer.apple.com/documentation/uikit/uipasteboard) API, apps can access the iOS pasteboard, allowing them to share data either within the app or across apps. However, the system-wide nature of the general pasteboard raises privacy and security concerns, especially when sensitive data is copied programmatically without user interaction.

There are two types of pasteboards:

- **General pasteboard (`UIPasteboard.general`)**: Shared across all foreground apps and, with [Universal Clipboard](https://support.apple.com/en-us/102430), potentially across Apple devices. It is persistent by default across device restarts and app reinstalls unless cleared. As of iOS 16, the general pasteboard requires user interaction for access.
- **Custom or Named Pasteboards (`UIPasteboard(name:create:)` and `UIPasteboard.withUniqueName()`)**: These are [private pasteboards](https://developer.apple.com/library/archive/documentation/StringsTextFonts/Conceptual/TextAndWebiPhoneOS/UsingCopy%2CCut%2CandPasteOperations/UsingCopy%2CCut%2CandPasteOperations.html) that are app- or team-specific, i.e., restricted to the app that created them or other apps from the same team ID. They are non-persistent by default since iOS 10 (deleted upon app termination and system reboot). Apple discourages the use of persistent custom pasteboards and recommends [using App Groups](https://developer.apple.com/documentation/Xcode/configuring-app-groups) for sharing data between apps of the same developer.

The iOS pasteboard API has gone through multiple changes which can impact both the user's privacy and security:

- Since iOS 9, access to the pasteboard has been restricted to apps running in the foreground, which significantly reduces the risk of passive clipboard sniffing. However, if sensitive data remains on the pasteboard and a malicious app is brought to the foreground later (or an app widget that remains in the foreground whenever the user is on the screen where it's located), the app can access that data without the user's consent or knowledge. See the [example attack](https://www.thedailybeast.com/facebook-is-spying-on-your-clipboard).
- Since iOS 10, Universal Clipboard is enabled by default and, when a user signs into iCloud, automatically syncs the general pasteboard content across the user's nearby Apple devices using the same iCloud account. Developers can choose to disable this by restricting the contents of the general pasteboard to the local device using `UIPasteboard.localOnly`. Additionally, they may set expiration times for pasteboard items using `UIPasteboard.expirationDate`.
- Since iOS 14, **the system notifies the user** when an app reads general pasteboard content that was written by a different app without user intent. The system determines user intent based on user interactions, such as tapping a system-provided button or selecting **Paste** from the contextual menu.
- Since iOS 16, the system prompts users with a paste confirmation dialog whenever an app accesses pasteboard content. Therefore, any access to the general pasteboard must be explicitly triggered by user interaction. Apps can also use [`UIPasteControl`](https://developer.apple.com/documentation/uikit/uipastecontrol) to handle paste actions by presenting a special "paste" button whenever they detect compatible data. This isn't necessarily better or more secure; it's an improvement to the user experience. It avoids prompting the user every time, but the user still needs to click, so access occurs only in response to user interaction.
