---
platform: ios
title: Sending data to trackers' domains
id: MASTG-TEST-0x54
type: [static, dynamic]
weakness: MASWE-0108
---

## Overview

This test checks if your app connects to tracker services that could monitor user behavior and display banner ads.

## Steps

1. Collect a list of potential trackers. You can use an open-source list like [lists](https://github.com/duckduckgo/tracker-blocklists/blob/main/app/android-tds.json).

2. Search statically with @MASTG-TOOL-0110 for deny listed domain names, or dynamically intercept network requests with @MASTG-TOOL-0097.

3. Review the list of used domains.

## Observation

The output should contain the list of:

- matched domains with the deny list (static analysis)
- all the domains that the app interacted with (dynamic analysis)

## Evaluation

The test case fails if you can find the use of a domain that is deny listed, its origin is unknown.
