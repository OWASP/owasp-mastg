#!/usr/bin/env python3

import sys
import os

# Add utils directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..', 'utils'))

from radare2.r2_utils import (
    init_r2, R2Context, setup_r2_environment, find_functions_by_pattern,
    analyze_function_usage, get_function_xrefs, disassemble_before,
    disassemble_function, print_section
)


def main():
    # Initialize binary path
    binary_path = init_r2(caller_file=__file__)
    
    # Use context manager for automatic cleanup
    with R2Context(binary_path) as r2:
        # Set equivalent options to the r2 script
        setup_r2_environment(r2, color=False, show_bytes=False, show_vars=False)
        
        # Uses of the CCCrypt function
        print_section("Uses of the CCCrypt function:")
        
        # Find functions with CCCrypt pattern
        cccrypt_functions = find_functions_by_pattern(r2, "CCCrypt")
        for func in cccrypt_functions:
            print(func)
        
        print()
        
        # Analyze CCCrypt function usage
        analysis = analyze_function_usage(r2, ["CCCrypt"])
        
        # Find the first used CCCrypt function
        target_addr = None
        for func_name, data in analysis.items():
            if data['xrefs']:  # Has cross-references (actually used)
                target_addr = data['address']
                break
        
        # Show xrefs for CCCrypt
        print_section("xrefs to CCCrypt:")
        if target_addr:
            xrefs = get_function_xrefs(r2, target_addr)
            for xref in xrefs:
                print(xref['raw'])
        
        print()
        print_section("Use of CCCrypt:")
        print()
        
        # Find the call site and disassemble around it
        if target_addr:
            xrefs = get_function_xrefs(r2, target_addr)
            if xrefs:
                first_xref = xrefs[0]
                call_addr = first_xref['to']
                func_name = first_xref['from']
                
                try:
                    # Disassemble 9 instructions before the call
                    disasm = disassemble_before(r2, call_addr, 9)
                    if disasm:
                        print(disasm)
                    
                    # Generate function.asm file 
                    func_disasm = disassemble_function(r2, func_name)
                    if func_disasm:
                        with open('function.asm', 'w') as f:
                            f.write(func_disasm)
                except:
                    pass


if __name__ == "__main__":
    main()