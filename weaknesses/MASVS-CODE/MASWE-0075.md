---
title: Enforced Updating Not Implemented
id: MASWE-0075
alias: enforced-updating
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-ARCH-9]
  masvs-v2: [MASVS-CODE-2]

refs:
- https://developer.android.com/guide/playcore/in-app-updates
- https://developer.android.com/reference/com/google/android/play/core/appupdate/AppUpdateManager
- https://medium.com/swlh/updating-users-to-the-latest-app-release-on-ios-ed96e4c76705
- https://gist.github.com/DineshKachhot/f63fcebceca6351fc982cafd38f6f05c
draft:
  description: Check if the app enforces updates e.g. via AppUpdateManager on Android.
    However, the backend would be enforcing this and not only the app locally.
  topics:
  - AppUpdateManager on Android
  - itunes check on app version on iOS
status: placeholder

---

