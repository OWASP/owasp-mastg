---
platform: ios
title: Dependencies with Known Vulnerabilities in the App's SBOM
id: MASTG-TEST-0275
type: [static, developer]
weakness: MASWE-0076
profiles: [L1, L2]
---

## Overview

This test case checks for dependencies with known vulnerabilities in iOS applications by using a Software Bill of Materials (SBOM). The SBOM should be in CycloneDX format, which is a standard for describing the components and dependencies of software.

## Steps

1. Either ask the development team to share a SBOM in CycloneDX format, or, if you have access to the original source code, create one following @MASTG-TECH-0132.
2. Upload the SBOM to @MASTG-TOOL-0132.
3. Inspect the @MASTG-TOOL-0132 project for the use of vulnerable dependencies.

## Observation

The output should include a list of dependencies with names and CVE identifiers, if any.

## Evaluation

The test case fails if you can find dependencies with known vulnerabilities.
