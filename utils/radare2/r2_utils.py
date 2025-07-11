#!/usr/bin/env python3
"""
OWASP MASTG Radare2 Utilities

Common utility functions for Radare2 binary analysis scripts.
Provides a consistent interface for r2pipe operations and reduces code duplication.
"""

import r2pipe
import sys
import os
from typing import Optional, List, Dict, Tuple


class R2Context:
    """Context manager for r2pipe operations with automatic cleanup."""
    
    def __init__(self, binary_path: str, analyze: bool = True):
        self.binary_path = binary_path
        self.analyze = analyze
        self.r2 = None
    
    def __enter__(self):
        self.r2 = r2pipe.open(self.binary_path)
        if self.analyze:
            self.r2.cmd("aaa")
        return self.r2
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.r2:
            self.r2.quit()


def init_r2(binary_path: Optional[str] = None, default_binary: str = "MASTestApp", caller_file: Optional[str] = None) -> str:
    """
    Initialize binary path from command line arguments or use default.
    
    Args:
        binary_path: Optional explicit binary path
        default_binary: Default binary name to look for in caller's directory
        caller_file: __file__ from the calling script for proper path resolution
        
    Returns:
        Resolved binary path
        
    Raises:
        SystemExit: If binary is not found
    """
    if binary_path is None:
        if len(sys.argv) > 1:
            binary_path = sys.argv[1]
        else:
            # Use caller's directory if provided, otherwise current working directory
            if caller_file:
                base_dir = os.path.dirname(os.path.abspath(caller_file))
            else:
                base_dir = os.getcwd()
            binary_path = os.path.join(base_dir, default_binary)
    
    if not os.path.exists(binary_path):
        print(f"Error: Binary not found at {binary_path}")
        sys.exit(1)
    
    return binary_path


def find_functions_by_pattern(r2: r2pipe.open, pattern: str) -> List[str]:
    """
    Find functions matching a specific pattern.
    
    Args:
        r2: r2pipe instance
        pattern: String pattern to search for in function names
        
    Returns:
        List of function lines containing the pattern
    """
    functions = r2.cmd("afl")
    matches = []
    for line in functions.split('\n'):
        if pattern in line and line.strip():
            matches.append(line.strip())
    return matches


def find_imports_by_pattern(r2: r2pipe.open, pattern: str) -> List[Dict[str, str]]:
    """
    Find imports matching a specific pattern.
    
    Args:
        r2: r2pipe instance
        pattern: String pattern to search for in import names
        
    Returns:
        List of dictionaries with 'address' and 'name' keys
    """
    imports = r2.cmd("ii")
    matches = []
    for line in imports.split('\n'):
        if pattern in line and line.strip():
            parts = line.split()
            if len(parts) >= 2 and parts[1] != '0x00000000':
                addr = parts[1]
                name = ' '.join(parts[4:]) if len(parts) > 4 else 'Unknown'
                matches.append({'address': addr, 'name': name})
    return matches


def get_function_xrefs(r2: r2pipe.open, addr: str) -> List[Dict[str, str]]:
    """
    Get cross-references to a function address.
    
    Args:
        r2: r2pipe instance
        addr: Function address
        
    Returns:
        List of dictionaries with 'from' and 'to' keys
    """
    xrefs = r2.cmd(f"axt @ {addr}")
    matches = []
    for line in xrefs.split('\n'):
        if line.strip():
            parts = line.split()
            if len(parts) >= 2:
                matches.append({
                    'from': parts[0],
                    'to': parts[1],
                    'raw': line.strip()
                })
    return matches


def find_used_functions(r2: r2pipe.open, candidates: List[Dict[str, str]]) -> Dict[str, str]:
    """
    Find which function addresses are actually referenced in the code.
    
    Args:
        r2: r2pipe instance
        candidates: List of candidate functions with 'address' key
        
    Returns:
        Dictionary mapping function names to addresses for used functions
    """
    used_functions = {}
    
    for candidate in candidates:
        addr = candidate['address']
        if addr == '0x00000000':
            continue
            
        xrefs = r2.cmd(f"axt @ {addr}")
        if xrefs.strip():
            name = candidate.get('name', 'Unknown')
            used_functions[name] = addr
    
    return used_functions


def disassemble_at(r2: r2pipe.open, addr: str, num_instructions: int) -> str:
    """
    Disassemble N instructions starting at address.
    
    Args:
        r2: r2pipe instance
        addr: Starting address
        num_instructions: Number of instructions to disassemble
        
    Returns:
        Disassembly string
    """
    try:
        return r2.cmd(f"pd {num_instructions} @ {addr}").strip()
    except:
        return ""


def disassemble_before(r2: r2pipe.open, addr: str, num_instructions: int) -> str:
    """
    Disassemble N instructions before address.
    
    Args:
        r2: r2pipe instance
        addr: Reference address
        num_instructions: Number of instructions to disassemble before
        
    Returns:
        Disassembly string
    """
    try:
        return r2.cmd(f"pd-- {num_instructions} @ {addr}").strip()
    except:
        return ""


def disassemble_function(r2: r2pipe.open, addr: str) -> str:
    """
    Disassemble entire function at address.
    
    Args:
        r2: r2pipe instance
        addr: Function address
        
    Returns:
        Function disassembly string
    """
    try:
        return r2.cmd(f"pdf @ {addr}").strip()
    except:
        return ""


def search_strings(r2: r2pipe.open, keywords: List[str]) -> List[str]:
    """
    Search for strings containing any of the specified keywords.
    
    Args:
        r2: r2pipe instance
        keywords: List of keywords to search for
        
    Returns:
        List of matching string lines
    """
    strings = r2.cmd("iz")
    matches = []
    
    for line in strings.split('\n'):
        if any(keyword.lower() in line.lower() for keyword in keywords):
            matches.append(line.strip())
    
    return matches


def find_string_addresses(r2: r2pipe.open, keywords: List[str]) -> List[Dict[str, str]]:
    """
    Find addresses of strings containing any of the specified keywords.
    
    Args:
        r2: r2pipe instance
        keywords: List of keywords to search for
        
    Returns:
        List of dictionaries with 'address' and 'content' keys
    """
    matches = []
    
    for keyword in keywords:
        string_search = r2.cmd(f"iz~+{keyword}")
        if string_search.strip():
            for line in string_search.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            # The vaddr is typically the 3rd column in iz output
                            addr = parts[2]
                            if addr.startswith('0x'):
                                matches.append({
                                    'address': addr,
                                    'content': ' '.join(parts[3:]) if len(parts) > 3 else keyword
                                })
                        except:
                            pass
    
    return matches


def search_binary(r2: r2pipe.open, search_terms: List[str]) -> Dict[str, List[str]]:
    """
    Search for specific terms in the binary.
    
    Args:
        r2: r2pipe instance
        search_terms: List of terms to search for
        
    Returns:
        Dictionary mapping search terms to lists of hits
    """
    results = {}
    
    for term in search_terms:
        hits = []
        result = r2.cmd(f"/q {term}")
        if result.strip():
            for line in result.strip().split('\n'):
                if 'hit' in line:
                    hits.append(line)
        results[term] = hits
    
    return results


def print_section(title: str, empty_lines_before: int = 1, empty_lines_after: int = 1):
    """
    Print a formatted section header.
    
    Args:
        title: Section title
        empty_lines_before: Number of empty lines before the title
        empty_lines_after: Number of empty lines after the title
    """
    print('\n' * empty_lines_before + title + '\n' * empty_lines_after, end='')


def analyze_function_usage(r2: r2pipe.open, function_patterns: List[str], 
                          context_keywords: List[str] = None) -> Dict[str, Dict]:
    """
    Analyze function usage patterns with context-aware matching.
    
    Args:
        r2: r2pipe instance
        function_patterns: List of patterns to search for in function names
        context_keywords: Optional keywords to help identify functions by context
        
    Returns:
        Dictionary with function analysis results
    """
    results = {}
    
    # Find candidate functions
    candidates = []
    for pattern in function_patterns:
        candidates.extend(find_imports_by_pattern(r2, pattern))
    
    # Find which functions are actually used
    used_functions = find_used_functions(r2, candidates)
    
    # For each used function, get detailed analysis
    for func_name, addr in used_functions.items():
        analysis = {
            'address': addr,
            'xrefs': get_function_xrefs(r2, addr),
            'name': func_name
        }
        
        # If context keywords provided, try to match them
        if context_keywords:
            for keyword in context_keywords:
                if keyword.lower() in func_name.lower():
                    analysis['context'] = keyword
                    break
        
        results[func_name] = analysis
    
    return results


def get_call_site_disassembly(r2: r2pipe.open, func_addr: str, instructions_before: int = 5) -> List[str]:
    """
    Get disassembly of call sites for a function.
    
    Args:
        r2: r2pipe instance
        func_addr: Function address
        instructions_before: Number of instructions to show before call site
        
    Returns:
        List of disassembly strings for each call site
    """
    disassemblies = []
    xrefs = get_function_xrefs(r2, func_addr)
    
    for xref in xrefs:
        call_addr = xref['to']
        disasm = disassemble_before(r2, call_addr, instructions_before)
        if disasm:
            disassemblies.append(disasm)
    
    return disassemblies


def setup_r2_environment(r2: r2pipe.open, color: bool = False, show_bytes: bool = False, 
                        show_vars: bool = False):
    """
    Set up r2 environment with common settings.
    
    Args:
        r2: r2pipe instance
        color: Enable colored output
        show_bytes: Show instruction bytes
        show_vars: Show variable names
    """
    r2.cmd(f"e scr.color={'true' if color else 'false'}")
    r2.cmd(f"e asm.bytes={'true' if show_bytes else 'false'}")
    r2.cmd(f"e asm.var={'true' if show_vars else 'false'}")