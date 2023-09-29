---
title: Basic Network Monitoring/Sniffing
platform: ios
---

You can remotely sniff all traffic in real-time on iOS by [creating a Remote Virtual Interface](https://stackoverflow.com/questions/9555403/capturing-mobile-phone-traffic-on-wireshark/33175819#33175819 "Wireshark + OSX + iOS") for your iOS device. First make sure you have [Wireshark](0x08a-Testing-Tools.md#wireshark) installed on your macOS host computer.

1. Connect your iOS device to your macOS host computer via USB.
2. You would need to know the UDID of your iOS device, before you can start sniffing. Check the section ["Getting the UDID of an iOS device"](#getting-the-udid-of-an-ios-device) on how to retrieve it. Open the Terminal on macOS and enter the following command, filling in the UDID of your iOS device.

```bash
$ rvictl -s <UDID>
Starting device <UDID> [SUCCEEDED] with interface rvi0
```

1. Launch Wireshark and select "rvi0" as the capture interface.
1. Filter the traffic with Capture Filters in Wireshark to display what you want to monitor (for example, all HTTP traffic sent/received via the IP address 192.168.1.1).

```default
ip.addr == 192.168.1.1 && http
```

<img src="Images/Chapters/0x06b/wireshark_filters.png" width="100%" />

The documentation of Wireshark offers many examples for [Capture Filters](https://wiki.wireshark.org/CaptureFilters "Capture Filters") that should help you to filter the traffic to get the information you want.
