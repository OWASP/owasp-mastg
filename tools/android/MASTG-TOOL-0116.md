---
title: Blutter
platform: android
source: https://github.com/worawit/blutter
---

[Blutter](https://github.com/worawit/blutter) is an open-source tool created to support the reverse engineering of Flutter applications. Unlike other Flutter tools, Blutter parses the libapp.so file locally, without requiring you to run the app on a device. The tool is compatible Linux, Windows, and macOS, but can only analyse Android ARM64 apps. Blutter is capable of extracting and analyzing Dart objects, it provides annotations for instructions, including function names or pool objects when applicable, and it can generate Frida scripts for further analysis.

This tool requires a specific environment to function. You can find the environment setup instructions [here](https://github.com/worawit/blutter?tab=readme-ov-file#environment-setup). Alternatively, if you prefer not to set up the environment manually, you can use the Docker file provided below.

```yml
# reference: https://github.com/worawit/blutter/pull/50

# Use Ubuntu 23.10 as the base image
FROM ubuntu:23.10

# Update and upgrade the system
RUN apt-get update && \
    apt-get upgrade -y

# Install necessary packages
RUN apt-get install -y \
    python3-pyelftools \
    python3-requests \
    git \
    cmake \
    ninja-build \
    build-essential \
    pkg-config \
    libicu-dev \
    libcapstone-dev

# Clone the specified repository
RUN git clone https://github.com/worawit/blutter.git

# Set the working directory to the cloned repository
WORKDIR /blutter

# Entry point for running the specific command
ENTRYPOINT ["python3", "blutter.py"]

# Default command arguments (can be overridden when running the container)
CMD ["/app/arm64-v8a", "/app/blutter_output"]
```

Reference:
[B(l)utter – Reversing Flutter Applications](https://www.youtube.com/watch?v=EU3KOzNkCdI)
