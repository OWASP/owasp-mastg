---
title: objection
platform: generic
source: https://github.com/sensepost/objection
---

[Objection](https://github.com/sensepost/objection "Objection on GitHub") is a "runtime mobile exploration toolkit, powered by Frida". Its main goal is to allow security testing on non-rooted devices through an intuitive interface.  You can find the [full list of features](https://github.com/sensepost/objection/wiki/Features) on the project's page, but here are a few platform-agnostic ones:

- Access application storage to download or upload files
- Execute custom Frida scripts
- Search, replace and dump memory
- Job control to unload hooks and scripts
- Interact with SQLite databases inline
- Support for custom plugins

Objection achieves this goal by providing you with the tools to easily inject the Frida gadget into an application by repackaging it. This way, you can deploy the repackaged app to the non-rooted/non-jailbroken device by sideloading it. Objection also provides a REPL that allows you to interact with the application, giving you the ability to perform any action that the application can perform.

Objection can be installed through pip as described on [Objection's Wiki](https://github.com/sensepost/objection/wiki/Installation "Objection Wiki - Installation").

```bash
pip3 install objection
```
