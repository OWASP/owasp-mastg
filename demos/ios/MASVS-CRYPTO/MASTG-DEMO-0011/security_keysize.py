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
        
        # Uses of SecKeyCreateRandomKey (equivalent to afl~SecKeyCreateRandomKey)
        print("Uses of SecKeyCreateRandomKey:")
        # Search for functions that contain "SecKeyCreateRandomKey" in their name from the afl output
        functions = r2.cmd("afl")
        for line in functions.split('\n'):
            if 'SecKeyCreateRandomKey' in line and line.strip():
                print(line.strip())
        
        print()
        
        # Find the addresses for SecKeyCreateRandomKey functions dynamically 
        target_addr = None
        
        # Use a more direct approach - search through imports by address
        # First, get all the SecKeyCreateRandomKey function addresses
        target_addrs = []
        imports = r2.cmd("ii")
        for line in imports.split('\n'):
            if 'SecKeyCreateRandomKey' in line:
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
        
        # xrefs to SecKeyCreateRandomKey
        print("xrefs to SecKeyCreateRandomKey:")
        if target_addr:
            xrefs = r2.cmd(f"axt @ {target_addr}")
            print(xrefs.strip())
        
        print()
        
        # Use of reloc.kSecAttrKeySizeInBits as input for SecKeyCreateRandomKey
        print("Use of reloc.kSecAttrKeySizeInBits as input for SecKeyCreateRandomKey:")
        
        # Instead of hardcoded addresses, we'll find the functions that use SecKeyCreateRandomKey
        if target_addr:
            calls = r2.cmd(f"axt @ {target_addr}")
            if calls.strip():
                lines = calls.strip().split('\n')
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 1:
                        # Get the function that contains this call
                        func_name = parts[0]
                        if 'sym.func.' in func_name or 'fcn.' in func_name:
                            # Extract function address or try to disassemble
                            try:
                                # Get one instruction from the beginning of the function
                                disasm = r2.cmd(f"pd 1 @ {func_name}")
                                print(disasm.strip())
                                break
                            except:
                                pass
        
        print()
        print("...")
        print()
        
        # Find specific addresses mentioned in the original by looking at the call sites
        if target_addr:
            calls = r2.cmd(f"axt @ {target_addr}")
            if calls.strip():
                lines = calls.strip().split('\n')
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            call_addr = parts[1]  # The address where the call is made
                            # Get 9 instructions from around this call
                            disasm = r2.cmd(f"pd 9 @ {call_addr}")
                            if disasm.strip():
                                print(disasm.strip())
                                break
                        except:
                            pass
        
        print()
        print("...")
        print()
        
        # Try to find the other address pattern mentioned (0x1000049a0 in original)
        if target_addr:
            calls = r2.cmd(f"axt @ {target_addr}")
            if calls.strip():
                lines = calls.strip().split('\n')
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            call_addr = parts[1]  # The address where the call is made
                            # Get 2 instructions before this address
                            # We'll look for instructions that end in 'a0' as mentioned in original
                            addr_int = int(call_addr, 16)
                            # Look around the address for potential matches
                            for offset in [0x50, 0x100, 0x150]:
                                test_addr = f"0x{addr_int + offset:x}"
                                disasm = r2.cmd(f"pd-- 2 @ {test_addr}")
                                if disasm.strip():
                                    # Check if this looks like key size related code
                                    if any(keyword in disasm.lower() for keyword in ['key', 'size', 'bits', 'attr']):
                                        print(disasm.strip())
                                        return
                        except:
                            pass
        
    finally:
        r2.quit()


if __name__ == "__main__":
    main()