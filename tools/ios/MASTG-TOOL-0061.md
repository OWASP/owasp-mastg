---
title: Grapefruit
platform: ios
source: https://github.com/ChiChou/grapefruit
---

[Grapefruit](https://github.com/ChiChou/grapefruit "Grapefruit") is an iOS app assessment tool that is using the Frida server on the iOS device and is abstracting many penetration testing tasks into a Web UI. It can be installed via `npm`.

```bash
$ npm install -g igf
$ grapefruit
listening on http://localhost:31337
```

When you execute the command `grapefruit` a local server will be started on port 31337. Connect your jailbroken device with the Frida server running, or a non-jailbroken device with a repackaged app including Frida to your machine via USB. Once you click on the "iPhone" icon you will get an overview of all installed apps.

With Grapfruit it's possible to explore different kinds of information concerning an iOS app. Once you selected the iOS app you can perform many tasks such as:

- Get information about the binary
- View folders and files used by the application and download them
- Inspect the Info.plist
- Get a UI Dump of the app screen shown on the iOS device
- List the modules that are loaded by the app
- Dump class names
- Dump keychain items
