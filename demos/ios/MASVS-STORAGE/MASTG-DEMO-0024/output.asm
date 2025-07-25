Uses of NSLog:
0x10000c6a4    1 12           sym.imp.Foundation.NSLog_Swift.String__Swift.CVarArg..._______

xrefs to NSLog:
(nofunc) 0x100000120 [UNKNOWN] invalid
sym.__s10MASTestApp9MastgTestV05mastgD010completionyySSc_tFZ 0x100004304 [CALL] bl sym.imp.Foundation.NSLog_Swift.String__Swift.CVarArg..._______

Invocation of NSLog:
│           0x1000042f0      bl sym Swift._allocateUninitializedArray<A>(Builtin.Word) -> (Swift.Array<A>, Builtin.RawPointer) ; sym.imp.Swift._allocateUninitializedArray_A__Builtin.Word______Swift.Array_A___Builtin.RawPointer_
│           0x1000042f4      ldr x1, [var_c0h]                         ; 0x4 ; 4
│           0x1000042f8      mov x2, x0
│           0x1000042fc      ldr x0, [var_b0h]                         ; 0x4 ; 4
│           0x100004300      str x2, [var_b8h]
│           0x100004304      bl sym.imp.Foundation.NSLog_Swift.String__Swift.CVarArg..._______
│           0x100004308      ldr x0, [var_b8h]                         ; 0x4 ; 4
│           0x10000430c      bl sym.imp.swift_bridgeObjectRelease
│           0x100004310      ldr x0, [var_c0h]                         ; 0x4 ; 4
│           0x100004314      bl sym.imp.swift_bridgeObjectRelease
