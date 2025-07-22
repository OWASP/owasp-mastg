---
platform: ios
title: Monitor secrets in logs
code: [swift]
id: MASTG-DEMO-0023
test: MASTG-TEST-0024
---

### Sample

The code snippet below shows sample code that logs a sensitive token.

{{ ../MASTG-DEMO-0024/MastgTest.kt }}

### Steps

1. Install the app
2. Run `run.sh`
3. Exercise the app to trigger the logging
4. Close the app
5. Press Ctrl+C to stop capturing the logs

{{ run.sh }}

### Observation

The `output.txt` contains all device logs including the logged strings from the app. You might need to filter out relevant logs.

{{ output.txt }}

### Evaluation

The test fails because we can see `TOKEN=123` inside the logs at:

```text
MASTestApp(Foundation)[94322] <Notice>: NSLog: Leaking TOKEN=123 from NSLog
MASTestApp[94322] <Error>: logger.warning: Leaking TOKEN=123
MASTestApp[94322] <Error>: logger.error: Leaking TOKEN=123
```
