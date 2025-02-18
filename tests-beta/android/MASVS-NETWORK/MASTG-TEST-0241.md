---
title: Expired Certificate Pins
platform: android
id: MASTG-TEST-0241
type: [static]
weakness: MASWE-0047
---

## Overview

Apps can configure expiration dates for pinned certificates in the [Network Security Configuration]("../../../Document/0x05g-Testing-Network-Communication.md#certificate-pinning"). After the expiration date, the pin is no longer used and all installed CAs for that domain are trusted.

The goal of this test is to check if any expiration date is in the past.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Inspect the AndroidManifest.xml, and check if a `networkSecurityConfig` is set in the `<application>` tag. If yes, inspect the referenced file, and extract the expiration dates for every domain.

## Observation

The output should contain a list of expiration dates for pinned certificates.

## Evaluation

The test case fails if any expiration date is in the past.
