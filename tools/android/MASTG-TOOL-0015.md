---
title: Drozer
platform: android
source: https://github.com/WithSecureLabs/drozer
---

[drozer](https://github.com/WithSecureLabs/drozer "drozer on GitHub") a security testing framework for Android. that allows you to search for security vulnerabilities in apps and devices by assuming the role of an app interacting with Android Runtime, other apps' IPC endpoints, and the underlying OS.

drozer helps to reduce the time taken for Android security assessments by automating tedious and time-consuming tasks. It allows testers and reverse-engineers to:

- Discover and interact with the attack surface exposed by Android apps.
- Execute dynamic Java-code on a device, to avoid the need to compile and install small test scripts.

drozer runs both in Android emulators and on real devices. It does not require USB debugging or other development features to be enabled; so you can perform assessments on devices in their production state to get better results.

drozer can be easily extended with additional modules to find, test and exploit other weaknesses; this, combined with scripting possibilities, helps you to automate regression testing for security issues.

## Installing drozer

### Using pip
You can use `pip` to install the [latest release](https://github.com/WithSecureLabs/drozer/releases/latest "Latest release on GitHub") of drozer:

```
sudo pip install drozer-<version>.whl
```

### Using Docker
To help with making sure drozer can be run on all systems, a Docker container was created that has a working build of drozer.

- The Docker container and basic setup instructions can be found [here](https://hub.docker.com/r/withsecurelabs/drozer).
- Instructions on building your own Docker container can be found [here](https://github.com/WithSecureLabs/drozer/tree/develop/docker).

## Example Usage

### Installing the Agent

drozer can be installed using Android Debug Bridge (adb).

Download the latest drozer Agent [here](https://github.com/WithSecureLabs/drozer-agent/releases/latest).

`$ adb install drozer-agent.apk`

### Setup for session

You should now have the drozer Console installed on your PC, and the Agent running on your test device. Now, you need to connect the two and you’re ready to start exploring.

We will use the server embedded in the drozer Agent to do this.

You need to set up a suitable port forward so that your PC can connect to a TCP socket opened by the Agent inside the device or emulator. By default, drozer uses port 31415:

`$ adb forward tcp:31415 tcp:31415`

Now, launch the Agent, select the "Embedded Server" option and tap "Enable" to start the server. You should see a notification that the server has started.

### Start a session

On your PC, connect using the drozer Console:

`$ drozer console connect`

If using a real device, the IP address of the device on the network must be specified:

`$ drozer console connect --server 192.168.0.10`

You should be presented with a drozer command prompt:

```
selecting f75640f67144d9a3 (unknown sdk 4.1.1)  
dz>
```
The prompt confirms the Android ID of the device you have connected to, along with the manufacturer, model and Android software version.

### Using modules


## Other Drozer resources

Other resources where you might find useful information are:

- [Official drozer User Manual](https://labs.withsecure.com/tools/drozer "drozer User Manual")
- [drozer GitHub page](https://github.com/WithSecureLabs/drozer "GitHub repo")
- [drozer Wiki](https://github.com/WithSecureLabs/drozer/wiki "drozer Wiki")