# Find the address of the CCCrypt function
afl~SecKeyCreateRandomKey

# Find all xrefs to CCCrypt (Replace the address with the one you find in the output)
axt @ 0x1000078ac

# Seek to the function where CCCrypt is called (Replace with the address found from axt output)
s sym.func.1000046f8

# Print the disassembly of the function
pdf
