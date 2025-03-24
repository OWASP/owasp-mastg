---
title: drozer
platform: android
source: https://github.com/WithSecureLabs/drozer
---

[drozer](https://github.com/WithSecureLabs/drozer "drozer on GitHub") is a security testing framework for Android that allows you to search for security vulnerabilities in apps and devices by assuming the role of an app interacting with the Android runtime, other apps' IPC endpoints, and the underlying OS.

drozer can be used during Android security assessments to automate tasks. It allows testers and reverse engineers to:

- Discover and interact with the attack surface exposed by Android apps.
- Execute dynamic Java-code on a device, to avoid the need to compile and install small test scripts.

drozer runs both in Android emulators and on real devices. It does not require USB debugging or other development features to be enabled; so you can perform assessments on devices in their production state to simulate attacks.

You can extend drozer with additional modules to find, test and exploit other weaknesses; this, combined with scripting possibilities, helps to automate regression testing for security issues.

## Installing drozer and Setup

Detailed instructions on how to install and set up the drozer console on your machine and the drozer agent on the Android phone can be found in the [drozer Github repo](https://github.com/WithSecureLabs/drozer "Installation instructions of drozer").

### Example usage

Once drozer is set up, you can use drozer to perform reconnaissance and exploitation of Android applications from the perspective of a malicious app on the device. [The drozer User Manual](https://labs.withsecure.com/tools/drozer#3 "drozer User Manual") introduces an intentionally vulnerable application - [sieve](https://github.com/WithSecureLabs/sieve "GitHub repo - sieve") - together with step-by-step exploitation instructions.

Some common drozer commands include:

#### Searching for applications on the device

```sh
run app.package.list -f <keyword>
```

This lists basic information about any packages containing the word "<keyword>" in their bundle identifier. This includes package names, key directories used by the application, and any permissions used or defined by the application.

#### Enumerating the attack surface of an app

```sh
run app.package.attacksurface <package>
```

This command inspects the target app's manifest and provides a report on any exported components of the application, and verifies whether the application is debuggable.

Once the attack surface has been identified, you can obtain more specific information about each component class. For example, to list Activities, you can use the following command:

```sh
run app.activity.info -a <package>
```

This lists the names of all exported Activities, together with the permissions required to interact with them.

#### Starting an Activity

In order to launch an exported activity, use the following command:

```sh
run app.activity.start --component <package> <component name>
```

When calling `app.activity.start`, you can build a much more complex intent. As with all drozer modules, you can request more usage information by using the `help` command:

```sh
dz> help app.activity.start
Attempting to run shell module
usage: run app.activity.start [-h] [--action ACTION] [--category CATEGORY [CATEGORY ...]] [--component PACKAGE COMPONENT] [--data-uri DATA_URI] [--extra TYPE KEY VALUE] [--flags FLAGS [FLAGS ...]] [--mimetype MIMETYPE]
```

You can learn more about how intents are created by running `help intents`.

## Other drozer resources

Other resources where you might find useful information are:

- [Official drozer User Manual](https://labs.withsecure.com/tools/drozer "drozer User Manual")
- [drozer GitHub page](https://github.com/WithSecureLabs/drozer "GitHub repo - drozer")
- [drozer Agent GitHub page](https://github.com/WithSecureLabs/drozer-agent "GitHub repo - drozer-agent")
