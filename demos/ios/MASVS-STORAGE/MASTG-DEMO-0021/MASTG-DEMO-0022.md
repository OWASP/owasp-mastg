---
platform: android
title: Testing Memory for Sensitive Data
id: MASTG-DEMO-0022
code: [swift]
test: MASTG-TEST-0x60
---

### Sample

The following samples contain:

- The Swift code simulates retrieving a secret from a server, then stores the secret in memory.

{{ MastgTest.swift }}

### Steps

1. Install the target app on your device.
2. Run the application to trigger storing some information into the memory
3. Run `run.sh`
4. Close the app once you finish testing.

{{ run.sh }}

### Observation

We can see the string from the app's memory inside `output.txt`.

{{ output.txt }}

The app keeps a reference to `MAS_API_KEY=8767086b9f6f976g-a8df76` string.

### Evaluation

The test fails because MAS_API_KEY=8767086b9f6f976g-a8df76 is found in memory. Although our code doesn’t explicitly retain this string, the UI TextView does. This makes it challenging to completely remove strings that are currently displayed. While you might accept some strings remaining in memory, you should still monitor their presence. However, if the string isn’t displayed on the screen but still appears in memory, this test definitely fails.
