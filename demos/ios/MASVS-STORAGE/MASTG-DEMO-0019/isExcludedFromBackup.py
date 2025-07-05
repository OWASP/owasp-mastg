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
        
        # Uses of isExcludedFromBackup (equivalent to afl~isExcludedFromBackup)
        print("Uses of isExcludedFromBackup:")
        functions = r2.cmd("afl")
        for line in functions.split('\n'):
            if 'isExcludedFromBackup' in line and line.strip():
                print(line.strip())
        
        print()
        
        # Find the addresses for isExcludedFromBackup functions dynamically 
        target_addr = None
        
        # Search through imports by address
        target_addrs = []
        imports = r2.cmd("ii")
        for line in imports.split('\n'):
            if 'isExcludedFromBackup' in line:
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
        
        # xrefs to isExcludedFromBackup
        print("xrefs to isExcludedFromBackup:")
        if target_addr:
            xrefs = r2.cmd(f"axt @ {target_addr}")
            print(xrefs.strip())
        
        print()
        print("Use of isExcludedFromBackup:")
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
                            disasm = r2.cmd(f"pd-- 5 @ {call_addr}")
                            print(disasm.strip())
                            break
                        except:
                            pass
        
        print()
        print("Search for secret.txt:")
        
        # Search for the string "secret.txt"
        search_result = r2.cmd("/ secret.txt")
        if search_result.strip():
            # Extract just the hit information
            lines = search_result.split('\n')
            for line in lines:
                if 'hit' in line and 'secret.txt' in line:
                    print(line)
        
        print()
        print("Use of the string secret.txt:")
        
        # Find where secret.txt string is used
        # First find the string address
        strings = r2.cmd("iz")
        secret_txt_addr = None
        for line in strings.split('\n'):
            if 'secret.txt' in line:
                parts = line.split()
                if len(parts) >= 3:  # vaddr is typically the 3rd column
                    try:
                        secret_txt_addr = parts[2]
                        break
                    except:
                        pass
        
        if secret_txt_addr:
            # Find where this string is referenced
            xrefs = r2.cmd(f"axt @ {secret_txt_addr}")
            if xrefs.strip():
                lines = xrefs.strip().split('\n')
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            call_addr = parts[1]
                            disasm = r2.cmd(f"pd-- 5 @ {call_addr}")
                            print(disasm.strip())
                            break
                        except:
                            pass
        
        # Generate function.asm file (equivalent to pdf @ 0x100004594 > function.asm)
        if target_addr:
            calls = r2.cmd(f"axt @ {target_addr}")
            if calls.strip():
                lines = calls.strip().split('\n')
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            call_addr = parts[1]
                            # Generate the function disassembly
                            func_disasm = r2.cmd(f"pdf @ {call_addr}")
                            with open('function.asm', 'w') as f:
                                f.write(func_disasm)
                            break
                        except:
                            pass
        
    finally:
        r2.quit()


if __name__ == "__main__":
    main()