---
platform: android
title: Dependencies with Known Vulnerabilities in the App's SBOM
id: MASTG-TEST-0274
type: [static, developer]
weakness: MASWE-0076
profiles: [L1, L2]
---

## Overview

In this test case we are identifying dependencies with known vulnerabilities by relying on a Software Bill of Material (SBOM).

## Steps

1. Either ask the development team to share a SBOM in CycloneDX format, or, if you have access to the original source code, create one following @MASTG-TECH-0130.
2. Upload the SBOM to @MASTG-TOOL-0132.
3. Inspect the @MASTG-TOOL-0132 project for the use of vulnerable dependencies.

## Observation

The output should include a list of dependencies with names and CVE identifiers, if any.

## Evaluation

The test case fails if you can find dependencies with known vulnerabilities.
