---
platform: android
title: Runtime Use of Local File Access APIs in WebViews
alias: references-to-local-file-access-in-webviews
id: MASTG-TEST-0253
apis: [WebView, setAllowFileAccess, setAllowFileAccessFromFileURLs, setAllowUniversalAccessFromFileURLs]
type: [dynamic]
weakness: MASWE-0069
best-practices: []
status: draft
note: This test checks for references to methods from the `WebSettings` class used by Android WebViews which enable loading content from various sources, including local files.
---
