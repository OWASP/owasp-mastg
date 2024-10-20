---
platform: ios
title: Identify SwiftPM Dependencies with Known Vulnerabilities through usage of SBOM
id: MASTG-TEST-0217
type: [static]
weakness: MASWE-0076
---

## Overview

In this test case we are identifying SwiftPM dependencies with known vulnerabilities by relying on a Software Bill of Material (SBOM).

## Steps

1. Either ask the development team to share a SBOM in CycloneDX format, or create one by yourself and follow @MASTG-TECH-0113.

2. Open @MASTG-TOOL-0117 and inspect the project where the SBOM was uploaded for the use of vulnerable dependencies.

## Observation

The output should include the dependency and the CVE identifiers for any dependency with known vulnerabilities.

## Evaluation

The test case fails if you can find dependencies with known vulnerabilities.
