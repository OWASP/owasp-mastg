---
masvs_category: MASVS-PLATFORM
platform: android
title: Inter-Process Communication (IPC) Mechanisms
---

During implementation of a mobile application, developers may apply traditional techniques for IPC (such as using shared files or network sockets). The IPC system functionality offered by mobile application platforms should be used because it is much more mature than traditional techniques. Using IPC mechanisms with no security in mind may cause the application to leak or expose sensitive data.

The following is a list of Android IPC Mechanisms that may expose sensitive data:

- [Binder](https://developer.android.com/reference/android/os/Binder.html "Binder")
- [AIDL](https://developer.android.com/guide/components/aidl.html "AIDL")
- [Intents](https://developer.android.com/reference/android/content/Intent.html "Intent")
- [Content Providers](https://developer.android.com/reference/android/content/ContentProvider.html "ContentProvider")
- [Services](https://developer.android.com/guide/components/services.html "Services")
