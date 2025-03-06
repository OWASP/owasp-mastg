Interceptor.attach(ObjC.classes.LAContext["- canEvaluatePolicy:error:"].implementation, {
    onEnter(args) {
      console.log("LAcontext.canEvaluatePolicy("+args[2]+")");
    }
});
