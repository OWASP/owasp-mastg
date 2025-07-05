#!/usr/bin/env python3

import sys
import os

# Add utils directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..', 'utils'))

from radare2.r2_utils import (
    init_r2, R2Context, setup_r2_environment, find_functions_by_pattern,
    analyze_function_usage, get_function_xrefs, disassemble_before,
    disassemble_function, find_string_addresses, print_section
)


def main():
    # Initialize binary path
    binary_path = init_r2(caller_file=__file__)
    
    # Use context manager for automatic cleanup
    with R2Context(binary_path) as r2:
        # Set equivalent options to the r2 script
        setup_r2_environment(r2, color=False, show_bytes=False, show_vars=False)
        
        # Uses of isExcludedFromBackup
        print_section("Uses of isExcludedFromBackup:")
        
        # Find functions with isExcludedFromBackup pattern
        backup_functions = find_functions_by_pattern(r2, "isExcludedFromBackup")
        for func in backup_functions:
            print(func)
        
        print()
        
        # Analyze isExcludedFromBackup function usage
        analysis = analyze_function_usage(r2, ["isExcludedFromBackup"])
        
        # Find the first used isExcludedFromBackup function
        target_addr = None
        for func_name, data in analysis.items():
            if data['xrefs']:  # Has cross-references (actually used)
                target_addr = data['address']
                break
        
        # Show xrefs for isExcludedFromBackup
        print_section("xrefs to isExcludedFromBackup:")
        if target_addr:
            xrefs = get_function_xrefs(r2, target_addr)
            for xref in xrefs:
                print(xref['raw'])
        
        print()
        print_section("Use of isExcludedFromBackup:")
        print()
        
        # Find the call site and disassemble around it
        if target_addr:
            xrefs = get_function_xrefs(r2, target_addr)
            if xrefs:
                first_xref = xrefs[0]
                call_addr = first_xref['to']
                
                try:
                    # Disassemble 5 instructions before the call
                    disasm = disassemble_before(r2, call_addr, 5)
                    if disasm:
                        print(disasm)
                except:
                    pass
        
        print()
        print_section("Search for secret.txt:")
        
        # Search for the string "secret.txt"
        search_result = r2.cmd("/ secret.txt")
        if search_result.strip():
            # Extract just the hit information
            lines = search_result.split('\n')
            for line in lines:
                if 'hit' in line and 'secret.txt' in line:
                    print(line)
        
        print()
        print_section("Use of the string secret.txt:")
        
        # Find where secret.txt string is used
        secret_addrs = find_string_addresses(r2, ["secret.txt"])
        if secret_addrs:
            secret_txt_addr = secret_addrs[0]['address']
            
            # Find where this string is referenced
            xrefs = get_function_xrefs(r2, secret_txt_addr)
            if xrefs:
                first_xref = xrefs[0]
                call_addr = first_xref['to']
                
                try:
                    # Disassemble 5 instructions before the call
                    disasm = disassemble_before(r2, call_addr, 5)
                    if disasm:
                        print(disasm)
                except:
                    pass
        
        # Generate function.asm file
        if target_addr:
            xrefs = get_function_xrefs(r2, target_addr)
            if xrefs:
                first_xref = xrefs[0]
                call_addr = first_xref['to']
                
                try:
                    # Generate the function disassembly
                    func_disasm = disassemble_function(r2, call_addr)
                    if func_disasm:
                        with open('function.asm', 'w') as f:
                            f.write(func_disasm)
                except:
                    pass


if __name__ == "__main__":
    main()