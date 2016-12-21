### <a name="OMTG-RARE-004"></a>OMTG-RARE-004: Test Debugging Defenses

#### Overview

Debugging is a highly effective way of analyzing the runtime behaviour of an app. It allows the reverse engineer to step through the code, stop execution of the app at arbitrary point, inspect and modify the state of variables, and a lot more. 

(...TODO...) 

The app should either actively prevent debuggers from attaching, or terminate when a debugger is detected.

#### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

#### Black-box Testing

(... TODO ... testing in basic form vs. advanced defenses)

Testing this control is as simple as attempting to attach a debugger to the app which should either fail, or cause the app to terminate.

#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [link to relevant how-tos, papers, etc.]
