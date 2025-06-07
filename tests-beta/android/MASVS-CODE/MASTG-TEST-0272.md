---
platform: android
title: Identify Dependencies with Known Vulnerabilities in the Android Project
id: MASTG-TEST-0272
type: [static]
weakness: MASWE-0076
profiles: [L1, L2]
---

## Overview

In this test case we will identify dependencies in Android Studio and scan them with @MASTG-TOOL-0131.

## Steps

1. Follow @MASTG-TECH-0131 and execute a scan through the build environment of Android Studio by using Gradle.

## Observation

The output should include the dependency and the CVE identifiers for any dependency with known vulnerabilities.

## Evaluation

The test case fails if you can find dependencies with known vulnerabilities.
