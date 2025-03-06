Interceptor.attach(ObjC.classes.LAContext["- canEvaluatePolicy:error:"].implementation, {
  onEnter(args) {

      const LAPolicy = {
          1: ".deviceOwnerAuthenticationWithBiometrics",
          2: ".deviceOwnerAuthentication"
      };

      const policy = args[2].toInt32();

      const policyDescription = LAPolicy[policy] || "Unknown Policy";

      console.log("Intercepted: LAContext.canEvaluatePolicy(" + args[2] + ") # " + args[2] + " = " + policyDescription);

      // Get the caller backtrace
      console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
          .map(DebugSymbol.fromAddress).join("\n"));

  }
});
