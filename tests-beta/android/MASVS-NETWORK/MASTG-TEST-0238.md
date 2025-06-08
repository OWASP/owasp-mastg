---
title: Runtime Use of Network APIs Transmitting Cleartext Traffic
platform: android
id: MASTG-TEST-0238
type: [dynamic]
weakness: MASWE-0050
status: placeholder
note: Using Frida, you can trace all traffic of the app, mitigating the limitation of the dynamic analysis that you do not know which app, or which location is responsible for the traffic. Using Frida (and `.backtrace()`), you can be sure this is from the analyzed app, and know the exact location. A new limitation is then that all relevant networking APIs need to be instrumented.
profiles: [L1, L2]
---
