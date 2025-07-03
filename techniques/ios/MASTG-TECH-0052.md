---
title: Accessing the Device Shell
platform: ios
---

One of the most common things you do when testing an app is accessing the device shell. In this section we'll see how to access the iOS shell both remotely from your host computer with/without a USB cable and locally from the device itself.

## Remote Shell

In contrast to Android where you can easily access the device shell using the adb tool, on iOS you only have the option to access the remote shell via SSH. This also means that your iOS device must be jailbroken in order to connect to its shell from your host computer. For this section we assume that you've properly jailbroken your device and have either @MASTG-TOOL-0064 or Zebra installed. In the rest of the guide we will reference to Sileo, but the same packages should be available in Zebra.

<img src="Images/Tools/TOOL-0064-Sileo.png" width="400px" />

In order to enable SSH access to your iOS device you can install the OpenSSH package. Once installed, be sure to connect both devices to the same Wi-Fi network and take a note of the device IP address, which you can find in the **Settings -> Wi-Fi** menu and tapping once on the info icon of the network you're connected to.

You can now access the remote device's shell by running `ssh root@<device_ip_address>`, which will log you in as the root user:

```bash
$ ssh root@192.168.197.234
root@192.168.197.234's password:
iPhone:~ root#
```

Press Control + D or type `exit` to quit.

When accessing your iOS device via SSH consider the following:

- The default users are `root` and `mobile`.
- The default password for both is `alpine`.

> Remember to change the default password for both users `root` and `mobile` as anyone on the same network can find the IP address of your device and connect via the well-known default password, which will give them root access to your device.

If you forget your password and want to reset it to the default `alpine`:

1. Edit the file `/private/etc/master.password` on your jailbroken iOS device (using an on-device shell as shown below)
2. Find the lines:

   ```bash
    root:xxxxxxxxx:0:0::0:0:System Administrator:/var/root:/bin/sh
    mobile:xxxxxxxxx:501:501::0:0:Mobile User:/var/mobile:/bin/sh
   ```

3. Change `xxxxxxxxx` to `/smx7MYTQIi2M` (which is the hashed password `alpine`)
4. Save and exit

## Connect to a Device via SSH over USB

During a real black box test, a reliable Wi-Fi connection may not be available. In this situation, you can use @MASTG-TOOL-0069 to connect to your device's SSH server via USB.

Connect macOS to an iOS device by installing and starting @MASTG-TOOL-0055:

```bash
$ iproxy 2222 22
waiting for connection
```

The above command maps port `22` on the iOS device to port `2222` on localhost. You can also [make iproxy run automatically in the background](https://web.archive.org/web/20230828205901/https://iphonedevwiki.net/index.php/SSH_Over_USB) if you don't want to run the binary every time you want to SSH over USB.

With the following command in a new terminal window, you can connect to the device:

```bash
$ ssh -p 2222 mobile@localhost
mobile@localhost's password:
iPhone:~ mobile%
```

## On-device Shell App

While usually using an on-device shell (terminal emulator) might be very tedious compared to a remote shell, it can prove handy for debugging in case of, for example, network issues or check some configuration. For example, you can install [NewTerm 2](https://chariz.com/get/newterm "NewTerm 2") via Sileo for this purpose (it supports iOS 10.0 to 16.2 at the time of this writing).

In addition, there are a few jailbreaks that explicitly disable incoming SSH _for security reasons_. In those cases, it is very convenient to have an on-device shell app, which you can use to first SSH out of the device with a reverse shell, and then connect from your host computer to it.

Opening a reverse shell over SSH can be done by running the command `ssh -R <remote_port>:localhost:22 <username>@<host_computer_ip>`.

On the on-device shell app run the following command and, when asked, enter the password of the `mstg` user of the host computer:

```bash
ssh -R 2222:localhost:22 mstg@192.168.197.235
```

On your host computer run the following command and, when asked, enter the password of the `root` user of the iOS device:

```bash
ssh -p 2222 root@localhost
```
