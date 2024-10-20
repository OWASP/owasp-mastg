---
platform: ios
title: Usage of Dependencies with Known Vulnerabilities
id: MASTG-TEST-0215
type: [static]
weakness: MASWE-0076
---

## Overview

In this test case we are identifying dependencies with known vulnerabilities in iOS. Dependencies are integrated through dependency managers, and there might be one or more of them being used. We therefore need all of the relevant files created by them to analyse them with a SCA scanning tool.

## Steps

1. In order to do this in the most efficient way you would need to ask the developer(s) which dependency managers are being used and to share the relevant file(s) created by them. Follow @MASTG-TECH-0113 for on overview of the package managers, relevant files you can request for and how to use @MASTG-TOOL-0116.

2. Run a SCA analysis tool such as @MASTG-TOOL-0116 against the file(s) created by the dependency manager(s) and look for the use of vulnerable dependencies.

## Observation

The output should include the dependency, the CVE identifiers and 

## Evaluation

The test case fails if you can find dependencies with known vulnerabilities.
