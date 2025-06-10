---
platform: ios
title: Undeclared Known Tracking Domains
id: MASTG-TEST-0281
type: [static, dynamic]
weakness: MASWE-0108
profiles: [P]
---

## Overview

This test identifies whether the app communicates with known tracking domains that are not declared in the app's [Privacy Manifest](https://developer.apple.com/documentation/bundleresources/privacy_manifest_files). These include domains listed in sources like [DuckDuckGo iOS Trackers](https://github.com/duckduckgo/tracker-blocklists/blob/main/web/v5/ios-tds.json), which are associated with ad networks, analytics providers, and user profiling services.

## Steps

1. Obtain the app's privacy manifests (both main binary and dependencies).
2. Search statically with @MASTG-TOOL-0110 for tracking domain names, or dynamically intercept network requests with @MASTG-TOOL-0097.

## Observation

The output should contain:

- a list of tracking domains with which the app has interacted, or may interact.
- all the app's privacy manifests as files.

## Evaluation

The test case fails if the app communicates with a tracking domain that isn't declared in its privacy manifest.
