---
title: Re-Signing
platform: ios
---

Tampering with an app invalidates the code signature of the main executable, so it won't run on a non-jailbroken device.

You'll need to re-sign the IPA with your provisioning profile. This can be done in various ways with different tools:

- @MASTG-TOOL-0114
- @MASTG-TOOL-0115
- @MASTG-TOOL-0102

After re-signing you should be ready to run the modified app. Install the app on the device using @MASTG-TOOL-0054 and start the app by clicking on the app icon:

```bash
ios-deploy -b <name>.ipa
```
