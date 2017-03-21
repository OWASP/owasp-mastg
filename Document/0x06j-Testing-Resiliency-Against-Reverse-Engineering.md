## Testing Resiliency Against Reverse Engineering

### Testing Jailbreak Detection

#### Overview

In the context of reverse engineering defense, jailbreak detection mechansism are added to make it a bit more difficult to run the app on a jailbroken device, which in turn impedes some tools and techniques reverse engineers like to use. As is the case with most other defenses, jailbreak detection is not a very effective defense on its own, but having some checks sprinkled throughout the app can improve the effectiveness of the overall anti-tampering scheme. Typical jailbreak detection techniques on iOS include:

##### File-based Checks

Checking for the existence of files and directories typically associated with jailbreaks, such as:

~~~
/Applications/Cydia.app
/Applications/FakeCarrier.app
/Applications/Icy.app
/Applications/IntelliScreen.app
/Applications/MxTube.app
/Applications/RockApp.app
/Applications/SBSettings.app
/Applications/WinterBoard.app
/Applications/blackra1n.app
/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist
/Library/MobileSubstrate/DynamicLibraries/Veency.plist
/Library/MobileSubstrate/MobileSubstrate.dylib
/System/Library/LaunchDaemons/com.ikey.bbot.plist
/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist
/bin/bash
/bin/sh
/etc/apt
/etc/ssh/sshd_config
/private/var/lib/apt
/private/var/lib/cydia
/private/var/mobile/Library/SBSettings/Themes
/private/var/stash
/private/var/tmp/cydia.log
/usr/bin/sshd
/usr/libexec/sftp-server
/usr/libexec/ssh-keysign
/usr/sbin/sshd
/var/cache/apt
/var/lib/apt
/var/lib/cydia
/var/log/syslog
/var/tmp/cydia.log
~~~

##### Checking File Permissions

Attempting to write a file to the /private/ directory. This should only be successful on jailbroken devices.

~~~

NSError *error;
NSString *stringToBeWritten = @"This is a test.";
[stringToBeWritten writeToFile:@"/private/jailbreak.txt" atomically:YES
         encoding:NSUTF8StringEncoding error:&error];
if(error==nil){
   //Device is jailbroken
   return YES;
 } else {
   //Device is not jailbroken
   [[NSFileManager defaultManager] removeItemAtPath:@"/private/jailbreak.txt" error:nil];
 }

~~~

##### Checking Protocol Handlers

Attempting to open a Cydia URL. The Cydia app store, which is installed by default by practically every jailbreaking tool, installs the cydia:// protocol handler. 

~~~
if([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://package/com.example.package"]]){
~~~

##### Calling System APIs 

-- TODO [Fork-based check] --

Executing privileged actions. Calling the system() function with a NULL argument on a non jailbroken device will return ”0”; doing the same on a jailbroken device will return ”1”. This is since the function will check whether /bin/sh can be accessed, and this is only the case on jailbroken devices. Another possibility would be trying to write into a location outside the application’s sandbox. This can be done by having the application attempt to create a file in, for example, the /private directory. If the file is successfully created, it means the device is jailbroken.'

##### Using the Dynamic Loader

-- TODO [dyld-based check] --

##### SSH Loopback Connection

-- TODO [Connect to localhost:22] --

#### Bypassing Jailbreak Detection

-- TODO [Jailbreak detection general description] --

-- TODO [Frida-based bypass] --

Hooking Objective-C methods and native functions:

~~~~python
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

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

- CWE-XXX - Title
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] - Jailbreak Detection Methods on the Trustware Spiderlabs Blog - https://www.trustwave.com/Resources/SpiderLabs-Blog/Jailbreak-Detection-Methods/
- [2] - Dana Geist, Marat Nigmatullin: Jailbreak/Root Detection Evasion Study on iOS and Android - http://delaat.net/rp/2015-2016/p51/report.pdf

##### Tools

* Tool - Link
* Enjarify - https://github.com/google/enjarify

### Testing Anti-Debugging

#### Overview

Debugging is a highly effective way of analyzing the runtime behaviour of an app. It allows the reverse engineer to step through the code, stop execution of the app at arbitrary point, inspect and modify the state of variables, and a lot more.

-- TODO [Typical debugging defenses] --

~~~c
typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);

#define PT_DENY_ATTACH 31

void disable_gdb() {
    void* handle = dlopen(0, RTLD_GLOBAL | RTLD_NOW);
    ptrace_ptr_t ptrace_ptr = dlsym(handle, "ptrace");
    ptrace_ptr(PT_DENY_ATTACH, 0, 0, 0);
    dlclose(handle);
}
~~~

~~~c
void disable_gdb() {

	asm(
		"mov	r0, #31\n\t"	// PT_DENY_ATTACH
		"mov	r1, #0\n\t"
		"mov	r2, #0\n\t"
		"mov 	ip, #26\n\t"	// syscall no.
		"svc    0\n"
	);
}
~~~


~~~c
- (void)protectAgainstDebugger {
    int                 junk;
    int                 mib[4];
    struct kinfo_proc   info;
    size_t              size;
    
    info.kp_proc.p_flag = 0;
    
    // Initialize mib, which tells sysctl the info we want, in this case
    // we're looking for information about a specific process ID.
    
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();
    

    while(1) {
     
        size = sizeof(info);
        junk = sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, NULL, 0);
        assert(junk == 0);

        // We're being debugged if the P_TRACED flag is set.
        
        if ((info.kp_proc.p_flag & P_TRACED) != 0) {
            exit(0);
        }
        
        sleep(1);
        
    }
}
~~~

The app should either actively prevent debuggers from attaching, or terminate when a debugger is detected.

#### Bypassing Anti-Debugging Defenses

-- TODO [Bypass techniques] --

~~~c
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

#### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

#### Black-box Testing

-- TODO [Needs more detail] --

Attach a debugger to the running process. This  should either fail, or the app should terminate or misbehave when the debugger has been detected. For example, if ptrace(PT_DENY_ATTACH) has been called, gdb will crash with a segmentation fault:

Note that some anti-debugging implementations respond in a stealthy way so that changes in behaviour are not immediately apparent. For example, a soft token app might not visibly respond when a debugger is detected, but instead secretly alter the state of an internal variable so that an incorrect OTP is generated at a later point. Make sure to run through the complete workflow to determine if attaching the debugger causes a crash or malfunction.

#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [link to relevant how-tos, papers, etc.]

### Testing File Integrity Checks

#### Overview

-- TODO [Implementation from UnCrackable2] --

#### Bypassing File Integrity Checks

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

- CWE-XXX - Title
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Android Cracking Blog - http://androidcracking.blogspot.com/2011/06/anti-tampering-with-crc-check.html
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

* Tool - Link
* Enjarify - https://github.com/google/enjarify

### Testing Detection of Reverse Engineering Tools

#### Overview

[Provide a general description of the issue.]

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

- CWE-XXX - Title
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

* Tool - Link
* Enjarify - https://github.com/google/enjarify

### Testing Emulator Detection

#### Overview

[Provide a general description of the issue.]

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

- CWE-XXX - Title
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

* Tool - Link
* Enjarify - https://github.com/google/enjarify

### Testing Memory Integrity Checks

#### Overview

[Provide a general description of the issue.]

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

- CWE-XXX - Title
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

* Tool - Link
* Enjarify - https://github.com/google/enjarify

### Verifying Variablility of Tampering Responses

#### Overview

[Provide a general description of the issue.]

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

- CWE-XXX - Title
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

* Tool - Link
* Enjarify - https://github.com/google/enjarify

### Testing Simple Obfuscation

#### Overview

[Provide a general description of the issue.]

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

- CWE-XXX - Title
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

* Tool - Link
* Enjarify - https://github.com/google/enjarify

### Verifying Integration of Defenses

#### Overview

[Provide a general description of the issue.]

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

- CWE-XXX - Title
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

* Tool - Link
* Enjarify - https://github.com/google/enjarify

### Testing Device Binding

#### Overview

[Provide a general description of the issue.]

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

- CWE-XXX - Title
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

* Tool - Link
* Enjarify - https://github.com/google/enjarify

### Testing Advanced Anti-Debugging

#### Overview

[Provide a general description of the issue.]

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

- CWE-XXX - Title
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

* Tool - Link
* Enjarify - https://github.com/google/enjarify

### Testing Advanced Obfuscation

#### Overview

[Provide a general description of the issue.]

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

- CWE-XXX - Title
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

* Tool - Link
* Enjarify - https://github.com/google/enjarify
