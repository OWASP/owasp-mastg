---
platform: ios
title: Undeclared Known Tracking Domains
id: MASTG-TEST-0281
type: [static, dynamic]
weakness: MASWE-0108
profiles: [P]
---

## Overview

This test identifies whether the app properly declares all known tracking domains it may communicate with in the [`NSPrivacyTrackingDomains`](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacytrackingdomains) section of its [Privacy Manifest](https://developer.apple.com/documentation/bundleresources/privacy_manifest_files) files.

To perform this test, use one or more curated lists of known trackers. These lists include domains and identifiers associated with advertising networks, analytics providers, and user profiling services. They are commonly used in privacy-focused tools and browsers to detect and block tracking behavior.

Some example lists:

- **[DuckDuckGo iOS Trackers](https://github.com/duckduckgo/tracker-blocklists/blob/main/web/v5/ios-tds.json)**: Includes domains, matching rules, descriptions, and categories such as "Action Pixels," "Ad Fraud," "Ad Motivated Tracking," and "Advertising."
- **[Exodus Privacy Trackers](https://reports.exodus-privacy.eu.org/en/trackers/)**: Includes tracker names, categories (e.g., "Advertisement," "Analytics," "Profiling"), descriptions, and detection metadata such as network and code signatures.

These references can be used to match hardcoded or dynamically accessed domains within your app and verify whether appropriate declarations exist in the Privacy Manifest.

## Steps

1. Extract the app's privacy manifest files, including those from third-party SDKs or frameworks.
2. Run a static analysis scan using @MASTG-TOOL-0073:
    - Search for hardcoded references to known tracking domains.
    - Identify code references to well-known tracking libraries.
3. Perform network analysis with @MASTG-TOOL-0097:
    - Intercept and log all outbound network traffic.
    - Extract all domain names contacted during runtime.

## Observation

The output should contain:

- A list of all extracted privacy manifests from the app and its embedded components.
- A list of all domains contacted during dynamic testing.
- A list of code matches for known tracking domains or tracking libraries from static analysis.

## Evaluation

The test fails if:

- Any domain associated with known trackers is used by the app but not declared in the `NSPrivacyTrackingDomains` key of the manifest.
- Any tracking SDK or domain is identified in the code but not declared as a tracking domain in the `NSPrivacyTrackingDomains` key of the manifest.
