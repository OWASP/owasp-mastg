---
title: Sensitive Data Stored Unencrypted via the SharedPreferences API to the App Sandbox
platform: android
id: MASTG-TEST-0287
type: [static, dynamic]
weakness: MASWE-0006
best-practices: []
profiles: [L1, L2]
status: placeholder
note: This test checks if the app is using the SharedPreferences API to store sensitive data (e.g. user credentials, tokens) in an unencrypted format within the app's sandbox. This includes checking for the use of `SharedPreferences` without encryption as well as not using `EncryptedSharedPreferences` or similar secure storage mechanisms.
---
