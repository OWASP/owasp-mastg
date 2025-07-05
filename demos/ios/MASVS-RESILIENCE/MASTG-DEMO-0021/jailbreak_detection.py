#!/usr/bin/env python3

import r2pipe
import sys
import os


def main():
    # Get binary path from command line arguments or use default
    if len(sys.argv) > 1:
        binary_path = sys.argv[1]
    else:
        # Default to MASTestApp in the same directory
        binary_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "MASTestApp")
    
    if not os.path.exists(binary_path):
        print(f"Error: Binary not found at {binary_path}")
        sys.exit(1)
    
    # Open binary with r2pipe
    r2 = r2pipe.open(binary_path)
    
    try:
        # Set equivalent options to the r2 script
        r2.cmd("e asm.bytes=false")
        r2.cmd("e scr.color=false")
        r2.cmd("e asm.var=false")
        
        # Analyze the binary
        r2.cmd("aaa")
        
        print()
        
        # Search for jailbreak paths
        print("search for jailbreak path:")
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
        
        for path in jailbreak_paths:
            result = r2.cmd(f"/q {path}")  # Use /q for quiet search
            if result.strip():
                print(f"{path}:")
                # Parse the result to show just the hits
                lines = result.strip().split('\n')
                for line in lines:
                    if 'hit' in line:
                        print(line)
        
        print()
        
        # Search for URL schemes
        print("search for urlSchemes:")
        print()
        
        url_schemes = [
            "cydia://",
            "sileo://", 
            "zebra://",
            "filza://"
        ]
        
        for scheme in url_schemes:
            result = r2.cmd(f"/q {scheme}")  # Use /q for quiet search
            if result.strip():
                print(f"{scheme}:")
                lines = result.strip().split('\n')
                for line in lines:
                    if 'hit' in line:
                        print(line)
        
        print()
        
        # Search for suspicious environment variables
        print("search for suspiciousEnvVars:")
        print()
        
        env_vars = [
            "DYLD_INSERT_LIBRARIES",
            "DYLD_FRAMEWORK_PATH",
            "DYLD_LIBRARY_PATH"
        ]
        
        for var in env_vars:
            result = r2.cmd(f"/q {var}")  # Use /q for quiet search
            if result.strip():
                print(f"{var}:")
                lines = result.strip().split('\n')
                for line in lines:
                    if 'hit' in line:
                        print(line)
        
        print()
        
        # Search for strings containing "jail" (equivalent to iz~+jail)
        print("Searching for Jailbreak output:")
        print()
        
        strings = r2.cmd("iz")
        jail_strings = []
        for line in strings.split('\n'):
            if 'jail' in line.lower():
                jail_strings.append(line.strip())
        
        for jail_str in jail_strings:
            print(jail_str)
        
        print()
        print()
        
        # Find xrefs to jailbreak strings dynamically
        print("xrefs to Jailbreak strings:")
        
        # Instead of hardcoded address, find strings that contain jailbreak-related content
        # and get their addresses dynamically
        jailbreak_string_addr = None
        
        # Look for specific jailbreak-related strings in the binary
        jailbreak_keywords = ['jail', 'cydia', 'sileo', 'zebra', 'root', 'su']
        
        for keyword in jailbreak_keywords:
            # Search for the keyword in strings
            string_search = r2.cmd(f"iz~+{keyword}")
            if string_search.strip():
                # Try to extract address from the string listing
                lines = string_search.split('\n')
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            # The vaddr is typically the 3rd column in iz output
                            addr = parts[2]
                            if addr.startswith('0x'):
                                jailbreak_string_addr = addr
                                break
                        except:
                            pass
                if jailbreak_string_addr:
                    break
        
        # If we found a jailbreak string address, show its xrefs
        if jailbreak_string_addr:
            xrefs = r2.cmd(f"axt {jailbreak_string_addr}")
            print(xrefs.strip())
        else:
            # Fallback: try to find any function that might be related to jailbreak detection
            functions = r2.cmd("afl")
            for line in functions.split('\n'):
                if any(keyword in line.lower() for keyword in ['jail', 'root', 'check', 'detect']):
                    parts = line.split()
                    if len(parts) >= 1:
                        addr = parts[0]
                        xrefs = r2.cmd(f"axt {addr}")
                        if xrefs.strip():
                            print(f"Function at {addr}:")
                            print(xrefs.strip())
                            break
        
        print()
        
        # Disassemble jailbreak detection function
        print("Disassembled Jailbreak function:")
        print()
        
        # Find a function that might contain jailbreak detection logic
        jailbreak_func_addr = None
        
        # Method 1: Look for functions that reference jailbreak strings
        if jailbreak_string_addr:
            xrefs = r2.cmd(f"axt {jailbreak_string_addr}")
            if xrefs.strip():
                lines = xrefs.split('\n')
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 1:
                        # Extract the function address that references the string
                        func_ref = parts[0]
                        if func_ref.startswith('fcn.') or func_ref.startswith('sym.'):
                            # Get the address from the function name
                            if '.' in func_ref:
                                try:
                                    addr_part = func_ref.split('.')[-1]
                                    if len(addr_part) == 8:  # Hex address
                                        jailbreak_func_addr = f"0x{addr_part}"
                                        break
                                except:
                                    pass
        
        # Method 2: Search for functions that contain relevant strings in their disassembly
        if not jailbreak_func_addr:
            functions = r2.cmd("afl")
            for line in functions.split('\n'):
                parts = line.split()
                if len(parts) >= 1:
                    addr = parts[0]
                    try:
                        # Get a brief disassembly to check for jailbreak-related content
                        disasm = r2.cmd(f"pdf @ {addr}")
                        if any(keyword in disasm.lower() for keyword in ['jail', 'cydia', 'root', '/applications', '/usr/bin']):
                            jailbreak_func_addr = addr
                            break
                    except:
                        pass
        
        # Disassemble the jailbreak function if found
        if jailbreak_func_addr:
            disasm = r2.cmd(f"pdf @ {jailbreak_func_addr}")
            print(disasm.strip())
        else:
            print("No specific jailbreak function found")
        
    finally:
        r2.quit()


if __name__ == "__main__":
    main()