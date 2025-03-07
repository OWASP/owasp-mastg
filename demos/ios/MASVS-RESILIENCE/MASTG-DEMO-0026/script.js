Interceptor.attach(ObjC.classes.LAContext["- canEvaluatePolicy:error:"].implementation, {
  onEnter(args) {

      const LAPolicy = {
          1: ".deviceOwnerAuthenticationWithBiometrics",
          2: ".deviceOwnerAuthentication"
      };

      const policy = args[2].toInt32();
      const policyDescription = LAPolicy[policy] || "Unknown Policy";

      console.log("Intercepted: LAContext.canEvaluatePolicy(" + args[2] + ") # " + args[2] + " = " + policyDescription);

      // Function to print backtrace with a configurable number of lines (default: 5)
      function printBacktrace(maxLines = 8) {
          console.log("\nBacktrace:");
          let backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
              .map(DebugSymbol.fromAddress);

          for (let i = 0; i < Math.min(maxLines, backtrace.length); i++) {
              console.log(backtrace[i]);
          }
      }
      printBacktrace();
  }
});
