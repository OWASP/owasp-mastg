Java.perform(() => {

    // Function to print backtrace with a configurable number of lines (default: 8)
    function printBacktrace(maxLines = 8) {
        let Exception = Java.use("java.lang.Exception");
        let stackTrace = Exception.$new().getStackTrace().toString().split(",");

        console.log("\nBacktrace:");
        for (let i = 0; i < Math.min(maxLines, stackTrace.length); i++) {
            console.log(stackTrace[i]);
        }
    }

    // Hook StrictMode.setVmPolicy
    let StrictMode = Java.use('android.os.StrictMode');

    StrictMode.setVmPolicy.implementation = function (policy) {
        console.log("\n[*] StrictMode.setVmPolicy() called\n");

        // Java stack trace
        printBacktrace();

        console.log("Policy: " + policy);
        this.setVmPolicy(policy);
    };

    // Hook StrictMode.VmPolicy.Builder.penaltyLog
    let VmPolicyBuilder = Java.use('android.os.StrictMode$VmPolicy$Builder');

    VmPolicyBuilder.penaltyLog.implementation = function () {
        console.log("\n[*] StrictMode.VmPolicy.Builder.penaltyLog() called\n");

        // Java stack trace
        printBacktrace();

        return this.penaltyLog();
    };

    console.log("\n[+] Frida script loaded to detect StrictMode usage and penaltyLog calls.\n");
});