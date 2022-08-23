---
empty: "nada"
---

# Techniques


> Here we'll find links to tools because you perform a technique using a tool (e.g. [frida-trace](../tools.md#frida-trace)) to obtain a certain resource (e.g. a [method trace](resources.md#method-trace))

## Basic

From Document/0x05b-Basic-Security_Testing.md

### Accessing the Device Shell
### Host-Device Data Transfer
### Listing Installed Apps
### Obtaining and Extracting Apps
### Installing Apps
### Exploring the App Package

### Accessing App Data Directories
### Monitoring System Logs


## Advanced

From Document/0x05c-Reverse-Engineering-and-Tampering.md

### Disassembling and Decompiling
### Decompiling Java Code
### Disassembling Native Code

### Retrieving Strings
### Java and Kotlin Bytecode
### Native Code
### Cross References
### Java and Kotlin
### Native Code
### API Usage
### Network Communication
### Manual (Reversed) Code Review


### Basic Information Gathering
### Open Files
### Open Connections
### Loaded Native Libraries
### Sandbox Inspection
### Debugging
#### Debugging Release Apps
#### Debugging Native Code
### Tracing
#### Execution Tracing
#### Tracing System Calls

### Method Tracing

In contrast to method profiling, which tells you how frequently a method is being called, method tracing helps you to also determine its input and output values. This technique can prove to be very useful when dealing with applications that have a big codebase and/or are obfuscated.

As we will discuss shortly in the next section, [frida-trace](../../../Document/0x08-Testing-Tools.md#frida) offers out-of-the-box support for Android/iOS native code tracing and iOS high level method tracing. If you prefer a GUI-based approach you can use tools such as [RMS - Runtime Mobile Security](../../../Document/0x08-Testing-Tools.md#RMS-Runtime-Mobile-Security) which enables a more visual experience as well as include several convenience [tracing options](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security#3-hook-on-the-fly-classesmethods-and-trace-their-args-and-return-values).

#### Native Code Tracing
#### JNI Tracing
### Emulation-based Analysis
### Binary Analysis
### Symbolic Execution

### Repackaging
### Re-Signing
### The "Wait For Debugger" Feature
### Library Injection
### Patching the Application's Smali Code
### Patching Application's Native Library
### Preloading Symbols

### Getting Loaded Classes and their Methods
### Getting Loaded Libraries
### Method Hooking
### Process Exploration
### Memory Maps and Inspection
### In-Memory Search
### Memory Dump
### Dumping KeyStore Data
### Dumping KeyChain Data

