---
title: Accessing the Device Shell
platform: android
tools: [adb, termux] # read automatically from the tools/ links
---

One of the most common things you do when testing an app is accessing the device shell. In this section we'll see how to access the Android shell both remotely from your host computer with/without a USB cable and locally from the device itself.

## Remote Shell

In order to connect to the shell of an Android device from your host computer, [adb](0x08a-Testing-Tools.md#adb) is usually your tool of choice (unless you prefer to use remote SSH access, e.g. [via Termux](https://wiki.termux.com/wiki/Remote_Access#Using_the_SSH_server "Using the SSH server")).

For this section we assume that you've properly enabled Developer Mode and USB debugging as explained in "Testing on a Real Device". Once you've connected your Android device via USB, you can access the remote device's shell by running:

```bash
adb shell
```

> press Control + D or type `exit` to quit

Once in the remote shell, if your device is rooted or you're using the emulator, you can get root access by running `su`:

```bash
bullhead:/ $ su
bullhead:/ # id
uid=0(root) gid=0(root) groups=0(root) context=u:r:su:s0
```

> Only if you're working with an emulator you may alternatively restart adb with root permissions with the command `adb root` so next time you enter `adb shell` you'll have root access already. This also allows to transfer data bidirectionally between your host computer and the Android file system, even with access to locations where only the root user has access to (via `adb push/pull`). See more about data transfer in section "[Host-Device Data Transfer](#host-device-data-transfer "Host-Device Data Transfer")" below.

### Connect to Multiple Devices

If you have more than one device, remember to include the `-s` flag followed by the device serial ID on all your `adb` commands (e.g. `adb -s emulator-5554 shell` or `adb -s 00b604081540b7c6 shell`). You can get a list of all connected devices and their serial IDs by using the following command:

```bash
adb devices
List of devices attached
00c907098530a82c    device
emulator-5554    device
```

### Connect to a Device over Wi-Fi

You can also access your Android device without using the USB cable. For this you'll have to connect both your host computer and your Android device to the same Wi-Fi network and follow the next steps:

- Connect the device to the host computer with a USB cable and set the target device to listen for a TCP/IP connection on port 5555: `adb tcpip 5555`.
- Disconnect the USB cable from the target device and run `adb connect <device_ip_address>`. Check that the device is now available by running `adb devices`.
- Open the shell with `adb shell`.

However, notice that by doing this you leave your device open to anyone being in the same network and knowing the IP address of your device. You may rather prefer using the USB connection.

> For example, on a Nexus device, you can find the IP address at **Settings** -> **System** -> **About phone** -> **Status** -> **IP address** or by going to the **Wi-Fi** menu and tapping once on the network you're connected to.

See the full instructions and considerations in the [Android Developers Documentation](https://developer.android.com/studio/command-line/adb#wireless "Connect to a device over Wi-Fi").

### Connect to a Device via SSH

If you prefer, you can also enable SSH access. A convenient option is to use [Termux](0x08a-Testing-Tools.md#termux), which you can easily [configure to offer SSH access](https://wiki.termux.com/wiki/Remote_Access#Using_the_SSH_server "Using the SSH server") (with password or public key authentication) and start it with the command `sshd` (starts by default on port 8022). In order to connect to the Termux via SSH you can simply run the command `ssh -p 8022 <ip_address>` (where `ip_address` is the actual remote device IP). This option has some additional benefits as it allows to access the file system via SFTP also on port 8022.

## On-device Shell App

While usually using an on-device shell (terminal emulator) such as [Termux](0x08a-Testing-Tools.md#termux) might be very tedious compared to a remote shell, it can prove handy for debugging in case of, for example, network issues or to check some configuration.
