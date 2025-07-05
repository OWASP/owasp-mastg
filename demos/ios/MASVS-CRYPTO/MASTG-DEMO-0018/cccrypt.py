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
        
        # Uses of the CCCrypt function (equivalent to afl~CCCrypt)
        print("Uses of the CCCrypt function:")
        functions = r2.cmd("afl")
        for line in functions.split('\n'):
            if 'CCCrypt' in line and line.strip():
                print(line.strip())
        
        print()
        
        # Find the addresses for CCCrypt functions dynamically 
        target_addr = None
        
        # Search through imports by address
        target_addrs = []
        imports = r2.cmd("ii")
        for line in imports.split('\n'):
            if 'CCCrypt' in line:
                parts = line.split()
                if len(parts) >= 2 and parts[1] != '0x00000000':
                    addr = parts[1]
                    target_addrs.append(addr)
        
        # Now find which ones are actually called in the code
        for addr in target_addrs:
            if addr == '0x00000000':
                continue
            xrefs = r2.cmd(f"axt @ {addr}")
            if xrefs.strip():
                target_addr = addr
                break
        
        # xrefs to CCCrypt
        print("xrefs to CCCrypt:")
        if target_addr:
            xrefs = r2.cmd(f"axt @ {target_addr}")
            print(xrefs.strip())
        
        print()
        print("Use of CCCrypt:")
        print()
        
        # Find the call site and disassemble around it
        if target_addr:
            calls = r2.cmd(f"axt @ {target_addr}")
            if calls.strip():
                lines = calls.strip().split('\n')
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            call_addr = parts[1]  # The address where the call is made
                            disasm = r2.cmd(f"pd-- 9 @ {call_addr}")
                            print(disasm.strip())
                            
                            # Generate function.asm file 
                            func_disasm = r2.cmd(f"pdf @ {parts[0]}")
                            with open('function.asm', 'w') as f:
                                f.write(func_disasm)
                            break
                        except:
                            pass
        
    finally:
        r2.quit()


if __name__ == "__main__":
    main()