---
platform: ios
title: Common use Hardcoded keys
tools: [MASTG-TOOL-0105]
code: [swift]
id: MASTG-DEMO-0012
test: MASTG-TEST-0210
---

### Sample

{{ MastgTest.swift }}

### Steps

Let's run our semgrep rule against the sample code.

{{ ../../../../rules/mastg-ios-hardcoded-keys.yml }}

{{ run.sh }}

### Observation

The rule has identified two instances in the code file where hardcoded keys is used. The specified line numbers can be located in the original code for further investigation and remediation.

{{ output.txt }}

### Evaluation

Review each of the reported instances.

- Line 6, 9, 11 where variable 'keyString' uses the hardcoded encryption key.
