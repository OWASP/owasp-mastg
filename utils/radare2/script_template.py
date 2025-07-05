#!/usr/bin/env python3
"""
Template for converting .r2 scripts to Python with r2pipe using the common utilities.

This template shows how to use the shared radare2 utilities to create minimal,
maintainable scripts that follow the established patterns.

Usage:
1. Copy this template
2. Modify the PATTERNS and ANALYSIS_CONFIG constants for your specific use case
3. Customize the main() function as needed
4. Replace this docstring with specific functionality description
"""

import sys
import os

# Add utils directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..', 'utils'))

from radare2.r2_utils import (
    init_r2, R2Context, setup_r2_environment, find_functions_by_pattern,
    analyze_function_usage, get_function_xrefs, get_call_site_disassembly,
    disassemble_before, disassemble_function, search_binary, search_strings,
    find_string_addresses, print_section
)

# Configuration for the analysis - customize these for your specific script
ANALYSIS_CONFIG = {
    # Function patterns to search for
    'function_patterns': ['YourFunctionPattern'],
    
    # Context keywords to help identify specific functions (e.g., MD5, SHA1)
    'context_keywords': ['Keyword1', 'Keyword2'],
    
    # String patterns to search for in the binary
    'string_patterns': ['string1', 'string2'],
    
    # Binary search terms (for /q searches)
    'binary_search_terms': ['/path/to/search', 'url://scheme'],
    
    # R2 environment settings
    'r2_settings': {
        'color': False,
        'show_bytes': False,
        'show_vars': False
    }
}


def main():
    # Initialize binary path
    binary_path = init_r2(caller_file=__file__)
    
    # Use context manager for automatic cleanup
    with R2Context(binary_path) as r2:
        # Set up r2 environment
        setup_r2_environment(r2, **ANALYSIS_CONFIG['r2_settings'])
        
        print_section("", 2, 0)  # Two empty lines at start
        
        # Example 1: Function Analysis Pattern
        if ANALYSIS_CONFIG['function_patterns']:
            print_section("Uses of targeted functions:")
            
            # Find functions matching patterns
            for pattern in ANALYSIS_CONFIG['function_patterns']:
                functions = find_functions_by_pattern(r2, pattern)
                for func in functions:
                    print(func)
            
            print()
            
            # Analyze function usage with context-aware matching
            analysis = analyze_function_usage(
                r2, 
                ANALYSIS_CONFIG['function_patterns'],
                ANALYSIS_CONFIG.get('context_keywords')
            )
            
            # Show cross-references for each used function
            for func_name, data in analysis.items():
                if data['xrefs']:  # Only show functions that are actually used
                    print_section(f"xrefs to {func_name}:")
                    for xref in data['xrefs']:
                        print(xref['raw'])
                    print()
                    
                    # Show usage (disassembly around call sites)
                    print_section(f"Use of {func_name}:")
                    disassemblies = get_call_site_disassembly(r2, data['address'], 5)
                    if disassemblies:
                        print(disassemblies[0])  # Show first call site
                    print()
        
        # Example 2: String Search Pattern
        if ANALYSIS_CONFIG['string_patterns']:
            print_section("String Analysis:")
            
            # Search for strings containing keywords
            matching_strings = search_strings(r2, ANALYSIS_CONFIG['string_patterns'])
            for string_line in matching_strings:
                print(string_line)
            print()
            
            # Find string addresses and their cross-references
            string_addrs = find_string_addresses(r2, ANALYSIS_CONFIG['string_patterns'])
            if string_addrs:
                print_section("xrefs to found strings:")
                for string_data in string_addrs:
                    addr = string_data['address']
                    content = string_data['content']
                    print(f"String: {content}")
                    
                    xrefs = get_function_xrefs(r2, addr)
                    for xref in xrefs:
                        print(xref['raw'])
                print()
        
        # Example 3: Binary Search Pattern
        if ANALYSIS_CONFIG['binary_search_terms']:
            print_section("Binary Search Results:")
            
            # Use utility function for binary search
            search_results = search_binary(r2, ANALYSIS_CONFIG['binary_search_terms'])
            for term, hits in search_results.items():
                if hits:
                    print(f"{term}:")
                    for hit in hits:
                        print(hit)
            print()
        
        # Example 4: Function Disassembly Pattern
        if ANALYSIS_CONFIG['function_patterns']:
            # Find a function to disassemble (could be based on various criteria)
            analysis = analyze_function_usage(r2, ANALYSIS_CONFIG['function_patterns'])
            
            for func_name, data in analysis.items():
                if data['xrefs']:
                    print_section(f"Disassembled {func_name} function:")
                    
                    # Method 1: Disassemble the function that calls our target
                    first_xref = data['xrefs'][0]
                    calling_func = first_xref['from']
                    
                    disasm = disassemble_function(r2, calling_func)
                    if disasm:
                        print(disasm)
                        
                        # Optionally save to file
                        # with open('function.asm', 'w') as f:
                        #     f.write(disasm)
                    break


def template_customization_notes():
    """
    Notes for customizing this template:
    
    1. Update ANALYSIS_CONFIG with your specific patterns:
       - function_patterns: List of strings to search for in function names
       - context_keywords: Keywords to help identify specific function variants
       - string_patterns: Strings to search for in the binary
       - binary_search_terms: Terms to search for using radare2's /q command
    
    2. Modify the main() function structure:
       - Remove sections you don't need (function analysis, string search, etc.)
       - Add custom analysis logic specific to your script's purpose
       - Adjust the output format to match the original .r2 script
    
    3. Common patterns you can use:
       - Function finding: find_functions_by_pattern()
       - Cross-reference analysis: get_function_xrefs()
       - Disassembly: disassemble_at(), disassemble_before(), disassemble_function()
       - String operations: search_strings(), find_string_addresses()
       - Binary searching: search_binary()
    
    4. Output formatting:
       - Use print_section() for consistent section headers
       - Follow the original .r2 script's output format as closely as possible
    
    5. Error handling:
       - The utility functions handle most common errors
       - The R2Context manager ensures proper cleanup
       - Add specific error handling only where needed
    """
    pass


if __name__ == "__main__":
    main()