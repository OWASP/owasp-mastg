#!/usr/bin/env python3

import sys
import os

# Add utils directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..', 'utils'))

from radare2.r2_utils import (
    init_r2, R2Context, setup_r2_environment, search_binary, search_strings,
    find_string_addresses, get_function_xrefs, disassemble_function, 
    find_functions_by_pattern, print_section
)


def main():
    # Initialize binary path
    binary_path = init_r2(caller_file=__file__)
    
    # Use context manager for automatic cleanup
    with R2Context(binary_path) as r2:
        # Set equivalent options to the r2 script
        setup_r2_environment(r2, color=False, show_bytes=False, show_vars=False)
        
        print()
        
        # Search for jailbreak paths
        print_section("search for jailbreak path:")
        print()
        
        # List of jailbreak-related paths to search for
        jailbreak_paths = [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app", 
            "/Applications/Zebra.app",
            "/usr/sbin/sshd",
            "/usr/bin/ssh",
            "/var/cache/apt",
            "/var/lib/apt",
            "/var/lib/cydia",
            "/var/log/syslog",
            "/bin/bash",
            "/bin/sh",
            "/etc/apt",
            "/private/jailbreak.txt",
            "/private/var/mobile/Library/jailbreak.txt"
        ]
        
        # Use utility function for binary search
        path_results = search_binary(r2, jailbreak_paths)
        for path, hits in path_results.items():
            if hits:
                print(f"{path}:")
                for hit in hits:
                    print(hit)
        
        print()
        
        # Search for URL schemes
        print_section("search for urlSchemes:")
        print()
        
        url_schemes = [
            "cydia://",
            "sileo://", 
            "zebra://",
            "filza://"
        ]
        
        # Use utility function for binary search
        scheme_results = search_binary(r2, url_schemes)
        for scheme, hits in scheme_results.items():
            if hits:
                print(f"{scheme}:")
                for hit in hits:
                    print(hit)
        
        print()
        
        # Search for suspicious environment variables
        print_section("search for suspiciousEnvVars:")
        print()
        
        env_vars = [
            "DYLD_INSERT_LIBRARIES",
            "DYLD_FRAMEWORK_PATH",
            "DYLD_LIBRARY_PATH"
        ]
        
        # Use utility function for binary search
        env_results = search_binary(r2, env_vars)
        for var, hits in env_results.items():
            if hits:
                print(f"{var}:")
                for hit in hits:
                    print(hit)
        
        print()
        
        # Search for strings containing "jail" (equivalent to iz~+jail)
        print_section("Searching for Jailbreak output:")
        print()
        
        # Use utility function to search strings
        jail_strings = search_strings(r2, ['jail'])
        for jail_str in jail_strings:
            print(jail_str)
        
        print()
        print()
        
        # Find xrefs to jailbreak strings dynamically
        print_section("xrefs to Jailbreak strings:")
        
        # Look for jailbreak-related string addresses
        jailbreak_keywords = ['jail', 'cydia', 'sileo', 'zebra', 'root', 'su']
        string_addrs = find_string_addresses(r2, jailbreak_keywords)
        
        # If we found a jailbreak string address, show its xrefs
        if string_addrs:
            jailbreak_string_addr = string_addrs[0]['address']
            xrefs = get_function_xrefs(r2, jailbreak_string_addr)
            for xref in xrefs:
                print(xref['raw'])
        else:
            # Fallback: try to find any function that might be related to jailbreak detection
            jailbreak_funcs = find_functions_by_pattern(r2, 'jail')
            if not jailbreak_funcs:
                # Try other patterns
                for pattern in ['root', 'check', 'detect']:
                    jailbreak_funcs = find_functions_by_pattern(r2, pattern)
                    if jailbreak_funcs:
                        break
            
            if jailbreak_funcs:
                func_line = jailbreak_funcs[0]
                parts = func_line.split()
                if parts:
                    addr = parts[0]
                    xrefs = get_function_xrefs(r2, addr)
                    if xrefs:
                        print(f"Function at {addr}:")
                        for xref in xrefs:
                            print(xref['raw'])
        
        print()
        
        # Disassemble jailbreak detection function
        print_section("Disassembled Jailbreak function:")
        print()
        
        # Find a function that might contain jailbreak detection logic
        jailbreak_func_addr = None
        
        # Method 1: Look for functions that reference jailbreak strings
        if string_addrs:
            jailbreak_string_addr = string_addrs[0]['address']
            xrefs = get_function_xrefs(r2, jailbreak_string_addr)
            if xrefs:
                func_ref = xrefs[0]['from']
                if func_ref.startswith('fcn.') or func_ref.startswith('sym.'):
                    # Get the address from the function name
                    if '.' in func_ref:
                        try:
                            addr_part = func_ref.split('.')[-1]
                            if len(addr_part) == 8:  # Hex address
                                jailbreak_func_addr = f"0x{addr_part}"
                        except:
                            pass
        
        # Method 2: Search for functions that contain relevant strings in their disassembly
        if not jailbreak_func_addr:
            jailbreak_funcs = find_functions_by_pattern(r2, 'jail')
            if not jailbreak_funcs:
                # Try other patterns that might indicate jailbreak detection
                for pattern in ['root', 'cydia', 'applications']:
                    jailbreak_funcs = find_functions_by_pattern(r2, pattern)
                    if jailbreak_funcs:
                        break
            
            if jailbreak_funcs:
                func_line = jailbreak_funcs[0]
                parts = func_line.split()
                if parts:
                    jailbreak_func_addr = parts[0]
        
        # Disassemble the jailbreak function if found
        if jailbreak_func_addr:
            disasm = disassemble_function(r2, jailbreak_func_addr)
            if disasm:
                print(disasm)
            else:
                print("No specific jailbreak function found")
        else:
            print("No specific jailbreak function found")


if __name__ == "__main__":
    main()