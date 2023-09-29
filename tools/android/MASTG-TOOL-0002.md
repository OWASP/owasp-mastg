---
title: MobSF for Android
platform: android
source: https://github.com/MobSF/Mobile-Security-Framework-MobSF
---

After MobSF is done with its analysis, you will receive a one-page overview of all the tests that were executed. The page is split up into multiple sections giving some first hints on the attack surface of the application.

<img src="Images/Chapters/0x05b/mobsf_android.png" width="100%" />

The following is displayed:

- Basic information about the app and its binary file.
- Some options to:
    - View the `AndroidManifest.xml` file.
    - View the IPC components of the app.
- Signer certificate.
- App permissions.
- A security analysis showing known defects e.g. if the app backups are enabled.
- List of libraries used by the app binary and list of all files inside the unzipped APK.
- Malware analysis that checks for malicious URLs.

Refer to [MobSF documentation](https://github.com/MobSF/Mobile-Security-Framework-MobSF/wiki/1.-Documentation "MobSF documentation") for more details.
