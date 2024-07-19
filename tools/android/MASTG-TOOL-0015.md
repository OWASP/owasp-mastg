---
title: drozer
platform: android
source: https://github.com/WithSecureLabs/drozer
---

[drozer](https://github.com/WithSecureLabs/drozer "drozer on GitHub") is a security testing framework for Android that allows you to search for security vulnerabilities in apps and devices by assuming the role of an app interacting with the Android Runtime, other apps' IPC endpoints, and the underlying OS.

drozer can be used during Android security assessments to automate tasks. It allows testers and reverse-engineers to:

- Discover and interact with the attack surface exposed by Android apps.
- Execute dynamic Java-code on a device, to avoid the need to compile and install small test scripts.

drozer runs both in Android emulators and on real devices. It does not require USB debugging or other development features to be enabled; so you can perform assessments on devices in their production state to simulate attacks.

You can extend drozer with additional modules to find, test and exploit other weaknesses; this, combined with scripting possibilities, helps to automate regression testing for security issues.

## Installing drozer

### Using pip
You can use `pipx` (or `pip`) to install the [latest release](https://github.com/WithSecureLabs/drozer/releases/latest "Latest release on GitHub") of drozer:

```
pipx install ./drozer-*.whl
```

### Using Docker
To help with making sure drozer can be run on all systems, a Docker container was created that has a working build of drozer.

- You can find the Docker container and basic setup instructions [here](https://hub.docker.com/r/withsecurelabs/drozer).
- Instructions on building your own Docker container can be found [here](https://github.com/WithSecureLabs/drozer/tree/develop/docker).

### Installing the Agent

drozer's "Agent" application is required for interaction with the device. You can install it using the Android Debug Bridge (`adb`).

Download the latest drozer Agent [here](https://github.com/WithSecureLabs/drozer-agent/releases/latest).

`$ adb install drozer-agent.apk`

## Using drozer

### Setup for session

You should now have the drozer Console installed on your PC, and the Agent running on your test device. Now, you need to connect the two and you’re ready to start exploring.

We will use the server embedded in the drozer Agent to do this. First, launch the Agent, select the "Embedded Server" option and tap "Enable" to start the server. You should see a notification that the server has started. 

Then, follow one of the options below.

#### Option 1: Connect to the phone via network

By default, the drozer Agent listens for incoming TCP connections on all interfaces on port 31415. In order to connect to the Agent, run the following command:

```
drozer console connect --server <phone's IP address>
```

If you are using the Docker container, the equivalent command would be:

```
docker run --net host -it withsecurelabs/drozer console connect --server <phone's IP address>
```

#### Option 2: Connect to the phone via USB

In some scenarios, connecting to the device over the network may not be viable. In these scenarios, you can leverage `adb`'s port-forwarding capabilities to establish a connection over USB.

First, you need to set up a suitable port forward so that your PC can connect to a TCP socket opened by the Agent inside the emulator, or on the device. By default, drozer uses port 31415

```
adb forward tcp:31415 tcp:31415
```

You can now connect to the drozer Agent by connecting to `localhost` (or simply not specifying the target IP)

```
drozer console connect
```

### Confirming a successful connection

You should be presented with a drozer command prompt:

```
Selecting ebe9fcc0c47b28da (Google sdk_gphone64_x86_64 12)

            ..                    ..:.
           ..o..                  .r..
            ..a..  . ....... .  ..nd
              ro..idsnemesisand..pr
              .otectorandroidsneme.
           .,sisandprotectorandroids+.
         ..nemesisandprotectorandroidsn:.
        .emesisandprotectorandroidsnemes..
      ..isandp,..,rotecyayandro,..,idsnem.
      .isisandp..rotectorandroid..snemisis.
      ,andprotectorandroidsnemisisandprotec.
     .torandroidsnemesisandprotectorandroid.
     .snemisisandprotectorandroidsnemesisan:
     .dprotectorandroidsnemesisandprotector.

drozer Console (v3.0.0)
dz>
```
The prompt confirms the Android ID of the device you have connected to, along with the manufacturer, model and Android OS version.

### Example usage

Once set up, you can use drozer to perform reconnaissance and exploitation of Android applications from the perspective of a malicious app on the device. [The drozer User Manual](https://labs.withsecure.com/tools/drozer#3 "drozer User Manual") introduces an intentionally vulnerable application - [sieve](https://github.com/WithSecureLabs/sieve "GitHub repo - sieve") - together with step-by-step exploitation instructions.

Some common drozer commands include:

#### Searching for applications on the device:
```
run app.package.list -f <keyword>
```
This lists basic informations about any packages containing the word "<keyword>" in their bundle identifier. This includes package names, key directories used by the application, and any permissions used or defined by the application.

#### Enumerating the attack surface of an app:
```
run app.package.attacksurface <package>
```
This command inspects the target app's manifest and provides a report on any exported components of the application, and verifies whether the application is debuggable.

Once the attack surface has been identified, you can obtain more specific information about each component class. For example, to list  Activities, you can use the following command:
```
run app.activity.info -a <package>
```
This lists the names of all exported Activities, together with the permissions required to interact with them.

#### Starting an Activity
In order to launch an exported activity, use the following command:
```
run app.activity.start --component <package> <component name>
```

When calling `app.activity.start`, you can build a much more complex intent. As with all drozer modules, you can request more usage information by using the command `help`:

```
dz> help app.activity.start
Attempting to run shell module
usage: run app.activity.start [-h] [--action ACTION] [--category CATEGORY [CATEGORY ...]] [--component PACKAGE COMPONENT] [--data-uri DATA_URI] [--extra TYPE KEY VALUE] [--flags FLAGS [FLAGS ...]] [--mimetype MIMETYPE]
```

You can learn more about how intents are created by running `help intents`.

#### Further information

Refer to the [Official drozer User Manual](https://labs.withsecure.com/tools/drozer "drozer User Manual") for a more comprehensive list of guided examples.

## Other drozer resources

Other resources where you might find useful information are:

- [Official drozer User Manual](https://labs.withsecure.com/tools/drozer "drozer User Manual")
- [drozer GitHub page](https://github.com/WithSecureLabs/drozer "GitHub repo - drozer")
- [drozer Agent GitHub page](https://github.com/WithSecureLabs/drozer-agent "GitHub repo - drozer-agent")