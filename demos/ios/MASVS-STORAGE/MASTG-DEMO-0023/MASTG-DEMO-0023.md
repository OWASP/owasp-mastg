---
platform: ios
title: Monitor secrets in logs
code: [swift]
id: MASTG-DEMO-0x53
test: MASTG-TEST-0024
---

### Sample

The code snippet below shows sample code that logs a sensitive token.

{{ MastgTest.swift }}

### Steps

1. Install the app
2. Run `run.sh`
3. Exercise the app to trigger the logging
4. Close the app
5. Press Ctrl+C to stop capturing the logs

{{ run.sh }}

### Observation

The `output.txt` contains all logged strings.

{{ output.txt }}

### Evaluation

The test fails because we can see `TOKEN=123` inside the logs.
