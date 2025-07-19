
const AccessControlFlags = {
    kSecAccessControlUserPresence: 1 << 0,
    kSecAccessControlBiometryAny: 1 << 1,
    kSecAccessControlBiometryCurrentSet: 1 << 3,
    kSecAccessControlDevicePasscode: 1 << 4,
    kSecAccessControlWatch: 1 << 5,
    kSecAccessControlOr: 1 << 14,
    kSecAccessControlAnd: 1 << 15,
    kSecAccessControlPrivateKeyUsage: 1 << 30,
    kSecAccessControlApplicationPassword: 1 << 31,
  };


Interceptor.attach(Module.getGlobalExportByName('SecAccessControlCreateWithFlags'), {
    /* 
        func SecAccessControlCreateWithFlags(
        _ allocator: CFAllocator?,
        _ protection: CFTypeRef,
        _ flags: SecAccessControlCreateFlags,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
        )  -> SecAccessControl?
    */
  onEnter(args) {
    const flags = args[2]
    const flags_description = parseAccessControlFlags(flags)
    console.log(`\SecAccessControlCreateWithFlags(..., 0x${flags.toString(16)}) called with ${flags_description}\n`)
    
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


function parseAccessControlFlags(value) {
    const result = [];
    for (const [name, bit] of Object.entries(AccessControlFlags)) {
      if ((value & bit) === bit) {
        result.push(name);
      }
    }
    return result;
  }
