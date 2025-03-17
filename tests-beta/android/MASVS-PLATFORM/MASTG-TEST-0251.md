---
platform: android
title: Runtime Use of Content Provider Access APIs in WebViews
alias: references-to-content-provider-access-in-webviews
id: MASTG-TEST-0251
apis: [WebView, ContentProvider, allowContentAccess]
type: [dynamic]
weakness: MASWE-0069
best-practices: []
status: draft
note: This test checks for references to Content Provider access in WebViews which is enabled by default and can be disabled using the `setAllowContentAccess` method in the `WebSettings` class. If improperly configured, this can introduce security risks such as unauthorized file access and data exfiltration.
---
