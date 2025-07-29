#!/usr/bin/env python3

import sys
import os

# Add utils directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..', 'utils'))

from radare2.r2_utils import (
    init_r2, R2Context, find_functions_by_pattern, find_imports_by_pattern,
    analyze_function_usage, get_call_site_disassembly, print_section
)


def main():
    # Initialize binary path
    binary_path = init_r2(caller_file=__file__)
    
    # Use context manager for automatic cleanup
    with R2Context(binary_path) as r2:
        print_section("", 2, 0)  # Two empty lines at start
        
        # Uses of CommonCrypto hash functions
        print_section("Uses of CommonCrypto hash function:")
        
        # Find functions and imports with "CC_" pattern
        cc_functions = find_functions_by_pattern(r2, "CC_")
        
        # Print all CC functions
        for func in cc_functions:
            print(func)
        
        print()
        
        # Analyze CommonCrypto function usage with context-aware matching
        analysis = analyze_function_usage(r2, ["CC_", "cc_"], ["MD5", "SHA1"])
        
        # Find MD5 and SHA1 functions by context
        md5_addr = None
        sha1_addr = None
        
        for func_name, data in analysis.items():
            if 'MD5' in func_name.upper() or data.get('context') == 'MD5':
                md5_addr = data['address']
            elif 'SHA1' in func_name.upper() or data.get('context') == 'SHA1':
                sha1_addr = data['address']
        
        # Show xrefs for MD5
        print_section("xrefs to CC_MD5:")
        if md5_addr and md5_addr in [data['address'] for data in analysis.values()]:
            for data in analysis.values():
                if data['address'] == md5_addr:
                    for xref in data['xrefs']:
                        print(xref['raw'])
        
        # Show xrefs for SHA1
        print_section("xrefs to CC_SHA1:")
        if sha1_addr and sha1_addr in [data['address'] for data in analysis.values()]:
            for data in analysis.values():
                if data['address'] == sha1_addr:
                    for xref in data['xrefs']:
                        print(xref['raw'])
        
        print()
        
        # Show MD5 usage
        print_section("Use of MD5:")
        if md5_addr:
            disassemblies = get_call_site_disassembly(r2, md5_addr, 5)
            if disassemblies:
                print(disassemblies[0])  # Show first call site
        
        print()
        
        # Show SHA1 usage  
        print_section("Use of SHA1:")
        if sha1_addr:
            disassemblies = get_call_site_disassembly(r2, sha1_addr, 5)
            if disassemblies:
                print(disassemblies[0])  # Show first call site


if __name__ == "__main__":
    main()