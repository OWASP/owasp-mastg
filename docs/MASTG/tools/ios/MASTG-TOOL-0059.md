---
title: optool
platform: ios
source: https://github.com/alexzielenski/optool
---

[optool](https://github.com/alexzielenski/optool) is a tool which interfaces with MachO binaries in order to insert/remove load commands, strip code signatures, resign, and remove aslr.

To install it:

```bash
git clone https://github.com/alexzielenski/optool.git
cd optool/
git submodule update --init --recursive
xcodebuild
ln -s <your-path-to-optool>/build/Release/optool /usr/local/bin/optool
```

The last line creates a symbolic link and makes the executable available system-wide. Reload your shell to make the new commands available:

```bash
zsh: # . ~/.zshrc
bash: # . ~/.bashrc
```