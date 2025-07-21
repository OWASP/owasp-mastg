---
masvs_category: MASVS-STORAGE
platform: ios
title: UserDefaults
---

The [`UserDefaults`](https://developer.apple.com/documentation/foundation/userdefaults "UserDefaults Class") class, part of the [`Preferences`](https://developer.apple.com/documentation/foundation/preferences "Preferences") API, provides a programmatic interface for storing key-value pairs across app launches. It stores data in a plist file within the app sandbox and is intended for small, non-sensitive data.

`UserDefaults` supports common types like `NSData`, `NSString`, `NSNumber`, `NSDate`, and `NSArray`. Other types must be converted to `NSData`.

Data is stored locally and included in device backups, except on managed educational devices.
