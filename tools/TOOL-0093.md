---
title: Angr
platform: android
---

Angr is a Python framework for analyzing binaries. It is useful for both static and dynamic symbolic ("concolic") analysis. In other words: given a binary and a requested state, Angr will try to get to that state, using formal methods (a technique used for static code analysis) to find a path, as well as brute forcing. Using angr to get to the requested state is often much faster than taking manual steps for debugging and searching the path towards the required state. Angr operates on the VEX intermediate language and comes with a loader for ELF/ARM binaries, so it is perfect for dealing with native code, such as native Android binaries.

Angr allows for disassembly, program instrumentation, symbolic execution, control-flow analysis, data-dependency analysis, decompilation and more, given a large set of plugins.

Since version 8, Angr is based on Python 3, and can be installed with pip on \*nix operating systems, macOS and Windows:

```bash
pip install angr
```

> Some of angr's dependencies contain forked versions of the Python modules Z3 and PyVEX, which would overwrite the original versions. If you're using those modules for anything else, you should create a dedicated virtual environment with [Virtualenv](https://docs.python.org/3/tutorial/venv.html "Virtualenv documentation"). Alternatively, you can always use the provided docker container. See the [installation guide](https://docs.angr.io/introductory-errata/install "angr Installation Guide") for more details.

Comprehensive documentation, including an installation guide, tutorials, and usage examples are available on [Angr's Gitbooks page](https://docs.angr.io/ "angr"). A complete [API reference](https://api.angr.io/ "angr API") is also available.

You can use angr from a Python REPL - such as iPython - or script your approaches. Although angr has a bit of a steep learning curve, we do recommend using it when you want to brute force your way to a given state of an executable. Please see the "[Symbolic Execution](0x05c-Reverse-Engineering-and-Tampering.md#symbolic-execution "Symbolic Execution")" section of the "Reverse Engineering and Tampering" chapter as a great example on how this can work.
