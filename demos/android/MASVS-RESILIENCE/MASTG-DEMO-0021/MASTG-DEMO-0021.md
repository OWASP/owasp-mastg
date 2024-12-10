---
title: Demonstration of RASP Presence in a Mobile Application
platform: android
code:   [kotlin]
id: MASTG-DEMO-0021
test: MASTG-TEST-0228
---

### Sample

The following code snippet demonstrates the implementation of the freeRASP security library SDK. freeRASP periodically scans the device for threats, monitors its state, and gathers data to generate detailed threat reports. Threats are detected and communicated to the app via listeners. In this example, the root detection scenario is simulated.

{{ MastgTest.kt }}

### Steps
Start the device, in this case, the Android emulator:
```bash
emulator -avd Pixel_3a_API_33_arm64-v8a -writable-system
```

**Note:** The snippet implements a simulated test for the freeRASP security library's root detection feature. The MastgTest class, which implements the ThreatDetected interface, includes various threat detection methods such as root detection, debugger detection, and emulator detection. The test specifically focuses on mocking the root detection functionality by invoking the onRootDetected() method, which logs the detection event and simulates app termination using the closeApp() method.

Launch the app from Android Studio and check the log. The snippet will log the “freeRASP Threat: onRootDetected”.


### Observation
The RASP policy is only configured for root detection, other threats are not evaluated. The threat was detected immediately after app start. Sample includes commented-out code to forcefully terminate the app.


### Evaluation
The app didn’t utilise all the available security checks. It would be possible to bypass freeRASP API with Frida script or disable the termination method.
