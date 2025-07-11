---
title: bettercap
platform: network
source: https://github.com/bettercap/bettercap
---

A powerful framework which aims to offer to security researchers and reverse engineers an easy to use, all-in-one solution for Wi-Fi, Bluetooth Low Energy, wireless HID hijacking and Ethernet networks reconnaissance. It can be used during network penetration tests in order to simulate a [Machine-in-the-Middle (MITM)](../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) attack. This is achieved by executing [ARP poisoning or spoofing](https://en.wikipedia.org/wiki/ARP_spoofing "ARP poisoning/spoofing") to the target computers. When such an attack is successful, all packets between two computers are redirected to a third computer that acts as the MITM and is able to intercept the traffic for analysis.

> bettercap is a powerful tool to execute MITM attacks and should be preferred nowadays, instead of ettercap. See also [Why another MITM tool?](https://www.bettercap.org/legacy/#why-another-mitm-tool "Why another MITM tool?") on the bettercap site.

bettercap is available for all major Linux and Unix operating systems and should be part of their respective package installation mechanisms. You need to install it on your host computer that will act as the MITM. On macOS it can be installed by using brew.

```bash
brew install bettercap
```

For Kali Linux you can install bettercap with `apt-get`:

```bash
apt-get update
apt-get install bettercap
```

There are installation instructions as well for Ubuntu Linux 18.04 on [LinuxHint](https://linuxhint.com/install-bettercap-on-ubuntu-18-04-and-use-the-events-stream/ "Install Bettercap on Ubuntu 18.04").
