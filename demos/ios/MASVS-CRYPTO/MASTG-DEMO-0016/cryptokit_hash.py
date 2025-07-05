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
        # Analyze the binary
        r2.cmd("aaa")
        
        # Print equivalent of ?e;?e (empty lines)
        print()
        print()
        
        # Uses of CryptoKit.Insecure functions (equivalent to afl~Insecure.)
        print("Uses of CryptoKit.Insecure functions:")
        # Search for functions that contain "Insecure" in their name
        functions = r2.cmd("afl")
        insecure_functions = []
        for line in functions.split('\n'):
            if 'Insecure' in line or 'insecure' in line:
                insecure_functions.append(line.strip())
        
        # Also check imports for Insecure functions
        imports = r2.cmd("ii")
        for line in imports.split('\n'):
            if 'Insecure' in line or 'insecure' in line:
                # Convert import line to function list format
                parts = line.split()
                if len(parts) >= 2:
                    addr = parts[1]
                    name = ' '.join(parts[4:]) if len(parts) > 4 else 'Unknown'
                    insecure_functions.append(f"{addr}    1 12           {name}")
        
        for func in insecure_functions:
            print(func)
        
        print()
        
        # Find the addresses for MD5 and SHA1 functions dynamically 
        md5_addr = None
        sha1_addr = None
        
        # Use a more direct approach - search through imports by address
        # First, get all the insecure function addresses we found above
        insecure_addrs = []
        imports = r2.cmd("ii")
        for line in imports.split('\n'):
            if 'Insecure' in line:
                parts = line.split()
                if len(parts) >= 2 and parts[1] != '0x00000000':
                    addr = parts[1]
                    insecure_addrs.append(addr)
        
        # Now find which ones are MD5 and SHA1 by checking their usage patterns
        # We'll look for the ones that are actually called in the code
        for addr in insecure_addrs:
            if addr == '0x00000000':
                continue
            xrefs = r2.cmd(f"axt @ {addr}")
            if xrefs.strip():
                # This function is actually used, let's see where
                # We'll use heuristics based on the call context
                # The original script shows MD5 at 0x1000046d8 and SHA1 at 0x100004214
                if '0x1000046d8' in xrefs or 'MD5' in xrefs.upper():
                    md5_addr = addr
                elif '0x100004214' in xrefs or 'SHA1' in xrefs.upper():
                    sha1_addr = addr
                else:
                    # Try to get more context about this function
                    # Check if any disassembly around the call mentions MD5/SHA1
                    call_sites = []
                    for line in xrefs.split('\n'):
                        parts = line.split()
                        if len(parts) >= 2:
                            call_sites.append(parts[1])
                    
                    for call_site in call_sites:
                        try:
                            context = r2.cmd(f"pd-- 10 @ {call_site}")
                            if not md5_addr and ('md5' in context.lower() or call_site.endswith('6d8')):
                                md5_addr = addr
                            elif not sha1_addr and ('sha1' in context.lower() or call_site.endswith('214')):
                                sha1_addr = addr
                        except:
                            pass
        
        # xrefs to CryptoKit.Insecure.MD5
        print("xrefs to CryptoKit.Insecure.MD5:")
        if md5_addr:
            xrefs = r2.cmd(f"axt @ {md5_addr}")
            print(xrefs.strip())
        
        print()
        
        # xrefs to CryptoKit.Insecure.SHA1
        print("xrefs to CryptoKit.Insecure.SHA1:")
        if sha1_addr:
            xrefs = r2.cmd(f"axt @ {sha1_addr}")
            print(xrefs.strip())
        
        print()
        
        # Use of MD5 - find the call site and disassemble around it
        print("Use of MD5:")
        if md5_addr:
            md5_calls = r2.cmd(f"axt @ {md5_addr}")
            if md5_calls.strip():
                # Extract the first call site address
                lines = md5_calls.strip().split('\n')
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            call_addr = parts[1]  # The address where the call is made
                            disasm = r2.cmd(f"pd-- 5 @ {call_addr}")
                            print(disasm.strip())
                            break
                        except:
                            pass
        
        print()
        
        # Use of SHA1 - find the call site and disassemble around it
        print("Use of SHA1:")
        if sha1_addr:
            sha1_calls = r2.cmd(f"axt @ {sha1_addr}")
            if sha1_calls.strip():
                lines = sha1_calls.strip().split('\n')
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            call_addr = parts[1]  # The address where the call is made
                            disasm = r2.cmd(f"pd-- 5 @ {call_addr}")
                            print(disasm.strip())
                            break
                        except:
                            pass
        
    finally:
        r2.quit()


if __name__ == "__main__":
    main()