---
title: Frida for iOS
platform: ios
source: https://github.com/frida/frida
---

Frida supports interaction with the Objective-C runtime through the [ObjC API](https://www.frida.re/docs/javascript-api/#objc "Frida - ObjC API"). You'll be able to hook and call both Objective-C and native functions inside the process and its native libraries. Your JavaScript snippets have full access to memory, e.g. to read and/or write any structured data.

Here are some tasks that Frida APIs offers and are relevant or exclusive on iOS:

- Instantiate Objective-C objects and call static and non-static class methods ([ObjC API](https://www.frida.re/docs/javascript-api/#objc "Frida - ObjC API")).
- Trace Objective-C method calls and/or replace their implementations ([Interceptor API](https://www.frida.re/docs/javascript-api/#interceptor "Frida - Interceptor API")).
- Enumerate live instances of specific classes by scanning the heap ([ObjC API](https://www.frida.re/docs/javascript-api/#objc "Frida - ObjC API")).
- Scan process memory for occurrences of a string ([Memory API](https://www.frida.re/docs/javascript-api/#memory "Frida - Memory API")).
- Intercept native function calls to run your own code at function entry and exit ([Interceptor API](https://www.frida.re/docs/javascript-api/#interceptor "Frida - Interceptor API")).

Remember that on iOS, you can also benefit from the built-in tools provided when installing Frida, which include the Frida CLI (`frida`), `frida-ps`, `frida-ls-devices` and `frida-trace`, to name a few.

There's a `frida-trace` feature exclusive on iOS worth highlighting: tracing Objective-C APIs using the `-m` flag and wildcards. For example, tracing all methods including "HTTP" in their name and belonging to any class whose name starts with "NSURL" is as easy as running:

```bash
frida-trace -U YourApp -m "*[NSURL* *HTTP*]"
```

For a quick start you can go through the [iOS examples](https://www.frida.re/docs/examples/ios/ "Frida iOS examples").

## Installing Frida on iOS

To connect Frida to an iOS app, you need a way to inject the Frida runtime into that app. This is easy to do on a jailbroken device since you can install `frida-server` through a third-party app store such as @MASTG-TOOL-0064. Open Sileo and add Frida's repository by navigating to **Manage** -> **Sources** -> **Edit** -> **Add** and entering <https://build.frida.re>. You should then be able to find and install the Frida package.

By default, `frida-server` only listens on the local interface, requiring you to connect the device over USB. If you want to expose `frida-server` on the public interface, modify `/var/jb/Library/LaunchDaemons/re.frida.server.plist` and two items to the `ProgramArguments` as shown below:

```xml
<?xml version="1.0" encoding="UTF-8"?> <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0"> <d>
        <key>Label</key>
        <string>re.frida.server</string>
        <key>Program</key>
        <string>/var/jb/usr/sbin/frida-server</string>
        <key>ProgramArguments</key>
        <array>
                <string>/var/jb/usr/sbin/frida-server</string>
                <string>-l</string>
                <string>0.0.0.0</string>
        </array>
        <key>UserName</key>
        <string>root</string>
        <key>POSIXSpawnType</key>
        <string>Interactive</string>
        <key>RunAtLoad</key>
        <true/>
        <key>KeepAlive</key>
        <true/>
        <key>ThrottleInterval</key>
        <integer>5</integer>
        <key>ExecuteAllowed</key>
        <true/>
</dict>
</plist>
```

Once it has been installed, the Frida server will automatically run with root privileges, allowing you to easily inject code into any process.

!!! danger

    Exposing frida-server on the public interface will let anyone connected on the same network to inject code into any process running on the device. You should only do this in a controlled lab environment.

## Using Frida on iOS

Connect your device via USB and make sure that Frida works by running the `frida-ps` command and the flag `-U`. This should return the list of processes running on the device:

```bash
$ frida-ps -U
PID  Name
---  ----------------
963  Mail
952  Safari
416  BTServer
422  BlueTool
791  CalendarWidget
451  CloudKeychainPro
239  CommCenter
764  ContactsCoreSpot
(...)
```

## Frida Bindings

In order to extend the scripting experience, Frida offers bindings to programming languages such as Python, C, NodeJS, and Swift.

Taking Python as an example, the first thing to note is that no further installation steps are required. Start your Python script with `import frida` and you're ready to go. See the following script that simply runs the previous JavaScript snippet:

```python
# frida_python.py
import frida

session = frida.get_usb_device().attach('com.android.chrome')

source = """
Java.perform(function () {
    var view = Java.use("android.view.View");
    var methods = view.class.getMethods();
    for(var i = 0; i < methods.length; i++) {
        console.log(methods[i].toString());
    }
});
"""

script = session.create_script(source)
script.load()

session.detach()
```

In this case, running the Python script (`python3 frida_python.py`) has the same result as the previous example: it will print all methods of the `android.view.View` class to the terminal. However, you might want to work with that data from Python. Using `send` instead of `console.log` will send data in JSON format from JavaScript to Python. Please read the comments in the example below:

```python
# python3 frida_python_send.py
import frida

session = frida.get_usb_device().attach('com.android.chrome')

# 1. we want to store method names inside a list
android_view_methods = []

source = """
Java.perform(function () {
    var view = Java.use("android.view.View");
    var methods = view.class.getMethods();
    for(var i = 0; i < methods.length; i++) {
        send(methods[i].toString());
    }
});
"""

script = session.create_script(source)

# 2. this is a callback function, only method names containing "Text" will be appended to the list
def on_message(message, data):
    if "Text" in message['payload']:
        android_view_methods.append(message['payload'])

# 3. we tell the script to run our callback each time a message is received
script.on('message', on_message)

script.load()

# 4. we do something with the collected data, in this case we just print it
for method in android_view_methods:
    print(method)

session.detach()
```

This effectively filters the methods and prints only the ones containing the string "Text":

```java
$ python3 frida_python_send.py
public boolean android.view.View.canResolveTextAlignment()
public boolean android.view.View.canResolveTextDirection()
public void android.view.View.setTextAlignment(int)
public void android.view.View.setTextDirection(int)
public void android.view.View.setTooltipText(java.lang.CharSequence)
...
```

In the end, it is up to you to decide where would you like to work with the data. Sometimes it will be more convenient to do it from JavaScript and in other cases Python will be the best choice. Of course you can also send messages from Python to JavaScript by using `script.post`. Refer to the Frida docs for more information about [sending](https://www.frida.re/docs/messages/#sending-messages-from-a-target-process "Sending messages from a target process") and [receiving](https://www.frida.re/docs/messages/#receiving-messages-in-a-target-process "Receiving messages in a target process") messages.
