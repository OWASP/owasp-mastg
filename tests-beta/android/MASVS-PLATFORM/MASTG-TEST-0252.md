---
platform: android
title: References to Local File Access in WebViews
alias: references-to-local-file-access-in-webviews
id: MASTG-TEST-0252
apis: [WebView, setAllowFileAccess, setAllowFileAccessFromFileURLs, setAllowUniversalAccessFromFileURLs]
type: [static]
weakness: MASWE-0069
best-practices: []
status: draft
note: This test checks for references to methods from the `WebSettings` class used by Android WebViews which enable loading content from various sources, including local files.
---
