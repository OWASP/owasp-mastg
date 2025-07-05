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
        
        # Uses of CommonCrypto hash function (equivalent to afl~CC_)
        print("Uses of CommonCrypto hash function:")
        # Search for functions that contain "CC_" in their name from the afl output
        functions = r2.cmd("afl")
        for line in functions.split('\n'):
            if 'CC_' in line and line.strip():
                print(line.strip())
        
        print()
        
        # Find the addresses for CC_MD5 and CC_SHA1 functions dynamically 
        md5_addr = None
        sha1_addr = None
        
        # Use a more direct approach - search through imports by address
        # First, get all the CC function addresses we found above
        cc_addrs = []
        imports = r2.cmd("ii")
        for line in imports.split('\n'):
            if 'CC_' in line or 'cc_' in line:
                parts = line.split()
                if len(parts) >= 2 and parts[1] != '0x00000000':
                    addr = parts[1]
                    cc_addrs.append(addr)
        
        # Now find which ones are MD5 and SHA1 by checking their usage patterns
        # We'll look for the ones that are actually called in the code
        for addr in cc_addrs:
            if addr == '0x00000000':
                continue
            xrefs = r2.cmd(f"axt @ {addr}")
            if xrefs.strip():
                # This function is actually used, let's see where
                # We'll use heuristics based on the call context
                # The original script shows MD5 at 0x1000048c4 and SHA1 at 0x10000456c
                if '0x1000048c4' in xrefs or 'MD5' in xrefs.upper():
                    md5_addr = addr
                elif '0x10000456c' in xrefs or 'SHA1' in xrefs.upper():
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
                            # Look for MD5/SHA1 patterns in the context
                            if not md5_addr and ('md5' in context.lower() or 'MD5' in context or call_site.endswith('8c4')):
                                md5_addr = addr
                            elif not sha1_addr and ('sha1' in context.lower() or 'SHA1' in context or call_site.endswith('56c')):
                                sha1_addr = addr
                        except:
                            pass
        
        # xrefs to CC_MD5
        print("xrefs to CC_MD5:")
        if md5_addr:
            xrefs = r2.cmd(f"axt @ {md5_addr}")
            print(xrefs.strip())
        
        # xrefs to CC_SHA1
        print("xrefs to CC_SHA1:")
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