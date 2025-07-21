---
masvs_category: MASVS-RESILIENCE
platform: ios
title: Emulator Detection
---

The goal of emulator detection is to increase the difficulty of running the app on an emulated device. This forces the reverse engineer to defeat the emulator checks or utilize the physical device, thereby barring the access required for large-scale device analysis.

As discussed in the section [Testing on the iOS Simulator](0x06b-iOS-Security-Testing.md#testing-on-the-ios-simulator "Testing on the iOS Simulator") in the basic security testing chapter, the only available simulator is the one that ships with Xcode. Simulator binaries are compiled to x86 code instead of ARM code and apps compiled for a real device (ARM architecture) don't run in the simulator, hence _simulation_ protection was not so much a concern regarding iOS apps in contrast to Android with a wide range of _emulation_ choices available.

However, since its release, [Corellium](https://www.corellium.com/) (commercial tool) has enabled real emulation, [setting itself apart from the iOS simulator](https://www.corellium.com/compare/ios-simulator "Corellium vs Apple\'s iOS Simulator"). In addition to that, being a SaaS solution, Corellium enables large-scale device analysis with the limiting factor just being available funds.

With Apple Silicon (ARM) hardware widely available, traditional checks for the presence of x86 / x64 architecture might not suffice. One potential detection strategy is to identify features and limitations available for commonly used emulation solutions. For instance, Corellium doesn't support iCloud, cellular services, camera, NFC, Bluetooth, App Store access or GPU hardware emulation ([Metal](https://developer.apple.com/documentation/metal/gpu_devices_and_work_submission/getting_the_default_gpu "Apple Metal Framework")). Therefore, smartly combining checks involving any of these features could be an indicator for the presence of an emulated environment.
