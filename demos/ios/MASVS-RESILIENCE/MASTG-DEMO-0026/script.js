Interceptor.attach(ObjC.classes.LAContext["- canEvaluatePolicy:error:"].implementation, {
  onEnter(args) {

      const LAPolicy = {
          1: ".deviceOwnerAuthenticationWithBiometrics",
          2: ".deviceOwnerAuthentication"
      };

      const policy = args[2].toInt32();
      const policyDescription = LAPolicy[policy] || "Unknown Policy";

      console.log(`\nLAContext.canEvaluatePolicy(${args[2]}) called with ${policyDescription} (${args[2]})\n`);

      // Use an arrow function so that `this` remains the same as in onEnter
      const printBacktrace = (maxLines = 8) => {
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
