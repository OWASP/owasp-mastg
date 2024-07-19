---
title: mitmproxy
platform: network
source: https://github.com/mitmproxy/mitmproxy/
---

[mitmproxy](https://mitmproxy.org/ "mitmproxy") is a free and open source interactive HTTPS intercepting proxy.

- **Command Line**: `mitmdump` is the command-line version of mitmproxy. Think tcpdump for HTTP. It can be used to intercept, inspect, modify and replay web traffic such as HTTP/1, HTTP/2, WebSockets, or any other SSL/TLS-protected protocols. You can prettify and decode a variety of message types ranging from HTML to Protobuf, intercept specific messages on-the-fly, modify them before they reach their destination, and replay them to a client or server later on.
- **Web Interface**: `mitmweb` is a web-based interface for mitmproxy. It gives you a similar experience as in Chrome's DevTools, plus additional features such as request interception and replay.
- **Python API**: Write powerful addons and script mitmproxy with mitmdump. The scripting API offers full control over mitmproxy and makes it possible to automatically modify messages, redirect traffic, visualize messages, or implement custom commands.

## Installation

```bash
brew install mitmproxy
```

The installation instructions are [here](https://docs.mitmproxy.org/stable/overview-installation).

## Usage

The documentation is [here](https://docs.mitmproxy.org/stable/). Mitmproxy starts as a regular HTTP proxy by default and listens on `http://localhost:8080`. You need to configure your browser or device to route all traffic through mitmproxy. For example, on Android emulator you need to follow the steps indicated [here](https://docs.mitmproxy.org/stable/howto-install-system-trusted-ca-android/).

For example, to capture all traffic to a file:

```bash
mitmdump -w outfile
```

This runs mitmproxy with the add_header.py script, which simply adds a new header to all responses.

```bash
mitmdump -s add_header.py
```
