---
masvs_category: MASVS-CODE
platform: ios
title: Debugging Code and Error Logging
---

To speed up verification and get a better understanding of errors, developers often include debugging code, such as verbose logging statements (using `NSLog`, `println`, `print`, `dump`, and `debugPrint`) about responses from their APIs and about their application's progress and/or state. Furthermore, there may be debugging code for "management-functionality", which is used by developers to set the application's state or mock responses from an API. Reverse engineers can easily use this information to track what's happening with the application. Therefore, debugging code should be removed from the application's release version.
