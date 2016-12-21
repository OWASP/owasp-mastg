### <a name="OMTG-RARE-004"></a>OMTG-RARE-004: Test Debugging Defenses

#### Overview

Debugging is a highly effective way of analyzing the runtime behaviour of an app. It allows the reverse engineer to step through the code, stop execution of the app at arbitrary point, inspect and modify the state of variables, and a lot more. 

(...TODO...) 

The app should either actively prevent debuggers from attaching, or terminate when a debugger is detected.

#### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

#### Black-box Testing

(... TODO ... testing in basic form vs. advanced defenses)

Attach a debugger to the running process. This  should either fail, or the app should terminate or misbehave when the debugger has been detected. For example, if ptrace(PT_DENY_ATTACH) has been called, gdb will crash with a segmentation fault:

(TODO example)

(TODO JDWP)

Note that some anti-debugging implementations respond in a stealthy way so that changes in behaviour are not immediately apparent. For example, a soft token app might not visibly respond when a debugger is detected, but instead secretly alter the state of an internal variable so that an incorrect OTP is generated at a later point. Make sure to run through the complete workflow to determine if attaching the debugger causes a crash or malfunction.


#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [link to relevant how-tos, papers, etc.]
