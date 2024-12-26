---
title: iProxy
platform: ios
source: https://github.com/libimobiledevice/libusbmuxd
---

iProxy allows you to forward a port from a connected iOS device to a port on the host machine. iProxy can be useful for interacting with jailbroken devices, as some jailbreaks do not expose the SSH port on the public interface. With iProxy, the SSH port can be forwarded over USB to the host, allowing you to still connect to it.

!!! warning

    While many package repositories (apt, brew, cargo, ...) have versions of libimobiledevice tools, they are often outdated. We recommend compiling the different tools from source for the best results.
