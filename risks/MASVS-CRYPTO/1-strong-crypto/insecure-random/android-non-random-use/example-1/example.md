---
platform: android
title: Common Uses of Insecure Random APIs
tools: [semgrep]
code: [java]
---

### Sample

{{ non-random.java }}

### Steps

Let's run our semgrep rule against the sample code.

{{ ../rules/mastg-android-non-random-use.yaml }}

{{ run.sh }}

### Observation

The rule has identified some instances in the code file where an non-random source is used. The specified line numbers can be located in the original code for further investigation and remediation.

{{ output.txt }}

### Evaluation

Review each of the reported instances.

{{ evaluation }}
