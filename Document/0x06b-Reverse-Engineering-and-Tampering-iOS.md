## Tampering and Reverse Engineering on iOS

### Basics

### Environment and Toolset

#### XCode and iOS SDK

#### Utilities

Class-dump by Steve Nygard is a command-line utility for examining the Objective-C runtime information stored in Mach-O files. It generates declarations for the classes, categories and protocols.

http://stevenygard.com/projects/class-dump/

Class-dump-dyld by Elias Limneos allows dumping and retrieving symbols directly from the shared cache, eliminating the need to extract the files first. It can generate header files from app binaries, libraries, frameworks, bundles or the whole dyld_shared_cache. Is is also possible to Mass-dump the whole dyld_shared_cache or directories recursively.

https://github.com/limneos/classdump-dyld/


### Jailbreaking an iOS Device

### Manipulating iOS Apps

### Hooking with MobileSubstrate

#### Example: Deactivating Anti-Debugging

~~~
#import <substrate.h>

#define PT_DENY_ATTACH 31

static int (*_my_ptrace)(int request, pid_t pid, caddr_t addr, int data);


static int $_my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
	if (request == PT_DENY_ATTACH) {
		request = -1;
	}
	return _ptraceHook(request,pid,addr,data);
}

%ctor {
	MSHookFunction((void *)MSFindSymbol(NULL,"_ptrace"), (void *)$ptraceHook, (void **)&_ptraceHook);
}
~~~


### Code Injection


#### Cynject

Cycript is traditionally used in the iOS world. It also runs standalone on Android, however without injection support. It is based on a Java VM that can be injected into a running process using Cydia Substrate. The user then communicates with process through the Cycript console interface.

Cycript injects a JavaScriptCore VM into the running process. Users can then manipulate the process using JavaScript with some syntax extensions through the Cycript Console.

*(Todo - use cases and example for Cycript)

- Obtain references to existing objects
- Instantiate objects from classes
- Hooking native functions
- Hooking objective-C methods
- etc.*
http://www.cycript.org/manual/

Cycript tricks:

http://iphonedevwiki.net/index.php/Cycript_Tricks

#### Frida

##### Example: Bypassing Jailbreak Detection

~~~~
import frida
import sys

try:
	session = frida.get_usb_device().attach("Target Process")
except frida.ProcessNotFoundError:
	print "Failed to attach to the target process. Did you launch the app?"
	sys.exit(0);

script = session.create_script("""

	// Handle fork() based check

  var fork = Module.findExportByName("libsystem_c.dylib", "fork");

	Interceptor.replace(fork, new NativeCallback(function () {
		send("Intercepted call to fork().");
	    return -1;
	}, 'int', []));

  var system = Module.findExportByName("libsystem_c.dylib", "system");

	Interceptor.replace(system, new NativeCallback(function () {
		send("Intercepted call to system().");
	    return 0;
	}, 'int', []));

	// Intercept checks for Cydia URL handler

	var canOpenURL = ObjC.classes.UIApplication["- canOpenURL:"];

	Interceptor.attach(canOpenURL.implementation, {
		onEnter: function(args) {
		  var url = ObjC.Object(args[2]);
		  send("[UIApplication canOpenURL:] " + path.toString());
		  },
		onLeave: function(retval) {
			send ("canOpenURL returned: " + retval);
	  	}

	});		

	// Intercept file existence checks via [NSFileManager fileExistsAtPath:]

	var fileExistsAtPath = ObjC.classes.NSFileManager["- fileExistsAtPath:"];
	var hideFile = 0;

	Interceptor.attach(fileExistsAtPath.implementation, {
		onEnter: function(args) {
		  var path = ObjC.Object(args[2]);
		  // send("[NSFileManager fileExistsAtPath:] " + path.toString());

		  if (path.toString() == "/Applications/Cydia.app" || path.toString() == "/bin/bash") {
		  	hideFile = 1;
		  }
		},
		onLeave: function(retval) {
			if (hideFile) {
		  		send("Hiding jailbreak file...");MM
				retval.replace(0);
				hideFile = 0;
			}

			// send("fileExistsAtPath returned: " + retval);
	  }
	});


	/* If the above doesn't work, you might want to hook low level file APIs as well

		var openat = Module.findExportByName("libsystem_c.dylib", "openat");
		var stat = Module.findExportByName("libsystem_c.dylib", "stat");
		var fopen = Module.findExportByName("libsystem_c.dylib", "fopen");
		var open = Module.findExportByName("libsystem_c.dylib", "open");
		var faccesset = Module.findExportByName("libsystem_kernel.dylib", "faccessat");

	*/

""")

def on_message(message, data):
	if 'payload' in message:
	  		print(message['payload'])

script.on('message', on_message)
script.load()
sys.stdin.read()
~~~~

### Reverse Engineering on iOS

#### Dumping Decrypted Executables

For iOS, distributed application package are usually stored in an IPA format which an archive file containing application bundles which contain executable binary, resource files, support files and application properties. But when an application is released to the App Store, application's binary will be encrypted by Apple's FairPlay (DRM). Therefore, to perform a static analysis, a binary of an application need to be decrypted first.

In order to analyze the iOS application from App Store, Tester need to decrypt the application which can be automatically conducted using “dumpdecrypted” tool developed by Stefan Esser.

To use “dumpdecrypted”, connect to the iOS device using SSH and set the DYLD_INSERT_LIBRARIES environment variable when executing the target binary:

~~~
ssh root@<ip of idevice>
iPod:root# DYLD_INSERT_LIBRARIES=dumpdecrypted.dylib /var/mobile/Applications/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/Example.app/Example
~~~

The decrypted binary is saved in the current working directory.

#### Analyzing Swift Apps


### Debugging iOS Apps

iOS ships with a console app, debugserver, that allows for remote debugging using gdb or lldb. By default however, debugserver cannot be used to attach to arbitrary processes (it is usually only used for debugging self-developed apps deployed with XCode). To enable debugging of third-part apps, the task_for_pid entitlement must be added to the debugserver executable. An easy way to do t


his is adding the entitlement to the debugserver binary shipped with XCode.

To obtain the executable mount the following DMG image:

~~~
/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/ DeviceSupport/<target-iOS-version//DeveloperDiskImage.dmg
~~~

You’ll find the debugserver executable in the /usr/bin/ directory on the mounted volume - copy it to a temporary directory. Then, create a file called entitlements.plist with the following content:

~~~
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/ PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.springboard.debugapplications</key>
	<true/>
	<key>run-unsigned-code</key>
	<true/>
	<key>get-task-allow</key>
	<true/>
	<key>task_for_pid-allow</key>
	<true/>
</dict>
</plist>
~~~

And apply the entitlement with codesign:

~~~
codesign -s - --entitlements entitlements.plist -f debugserver
~~~

Copy the modified binary to any directory on the test device (note: The following examples use usbmuxd to forward a local port through USB).

~~~
$ ./tcprelay.py -t 22:2222
$ scp -P2222 debugserver root@localhost:/tmp/
~~~

You can now attach debugserver to any process running on the device.

~~~
VP-iPhone-18:/tmp root# ./debugserver *:1234 -a 2670
debugserver-@(#)PROGRAM:debugserver  PROJECT:debugserver-320.2.89
 for armv7.
Attaching to process 2670...
~~~

Reference: http://iphonedevwiki.net/index.php/Debugserver
