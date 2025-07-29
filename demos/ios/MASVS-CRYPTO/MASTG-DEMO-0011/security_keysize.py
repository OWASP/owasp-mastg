#!/usr/bin/env python3

import sys
import os

# Add utils directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..', 'utils'))

from radare2.r2_utils import (
    init_r2, R2Context, find_functions_by_pattern, analyze_function_usage,
    get_function_xrefs, disassemble_at, print_section
)


def main():
    # Initialize binary path
    binary_path = init_r2(caller_file=__file__)
    
    # Use context manager for automatic cleanup
    with R2Context(binary_path) as r2:
        print_section("", 2, 0)  # Two empty lines at start
        
        # Uses of SecKeyCreateRandomKey
        print_section("Uses of SecKeyCreateRandomKey:")
        
        # Find functions with SecKeyCreateRandomKey pattern
        sec_functions = find_functions_by_pattern(r2, "SecKeyCreateRandomKey")
        
        # Print all matching functions
        for func in sec_functions:
            print(func)
        
        print()
        
        # Analyze SecKeyCreateRandomKey function usage
        analysis = analyze_function_usage(r2, ["SecKeyCreateRandomKey"])
        
        # Find the first used SecKeyCreateRandomKey function
        target_addr = None
        for func_name, data in analysis.items():
            if data['xrefs']:  # Has cross-references (actually used)
                target_addr = data['address']
                break
        
        # Show xrefs for SecKeyCreateRandomKey
        print_section("xrefs to SecKeyCreateRandomKey:")
        if target_addr:
            xrefs = get_function_xrefs(r2, target_addr)
            for xref in xrefs:
                print(xref['raw'])
        
        print()
        
        # Use of reloc.kSecAttrKeySizeInBits as input for SecKeyCreateRandomKey
        print_section("Use of reloc.kSecAttrKeySizeInBits as input for SecKeyCreateRandomKey:")
        
        if target_addr:
            xrefs = get_function_xrefs(r2, target_addr)
            if xrefs:
                # Get function containing the first call
                first_call = xrefs[0]
                func_name = first_call['from']
                if 'sym.func.' in func_name or 'fcn.' in func_name:
                    try:
                        # Get one instruction from the beginning of the function
                        disasm = disassemble_at(r2, func_name, 1)
                        if disasm:
                            print(disasm)
                    except:
                        pass
        
        print()
        print("...")
        print()
        
        # Find specific call sites and show detailed disassembly
        if target_addr:
            xrefs = get_function_xrefs(r2, target_addr)
            if xrefs:
                first_call = xrefs[0]
                call_addr = first_call['to']
                try:
                    # Get 9 instructions from around this call
                    disasm = disassemble_at(r2, call_addr, 9)
                    if disasm:
                        print(disasm)
                except:
                    pass
        
        print()
        print("...")
        print()
        
        # Try to find additional call patterns mentioned in original
        if target_addr:
            xrefs = get_function_xrefs(r2, target_addr)
            if xrefs:
                first_call = xrefs[0]
                call_addr = first_call['to']
                try:
                    addr_int = int(call_addr, 16)
                    # Look around the address for potential key size related code
                    for offset in [0x50, 0x100, 0x150]:
                        test_addr = f"0x{addr_int + offset:x}"
                        disasm = r2.cmd(f"pd-- 2 @ {test_addr}")
                        if disasm.strip():
                            # Check if this looks like key size related code
                            if any(keyword in disasm.lower() for keyword in ['key', 'size', 'bits', 'attr']):
                                print(disasm.strip())
                                return
                except:
                    pass


if __name__ == "__main__":
    main()