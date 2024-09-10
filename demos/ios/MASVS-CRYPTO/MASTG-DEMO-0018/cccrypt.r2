# Find the address of the CCCrypt function
afl~CCCrypt

# Find all xrefs to CCCrypt (Replace the address with the one you find in the output)
axt @ 0x1000076c4

# Seek to the function where CCCrypt is called (Replace with the address found from axt output)
s fcn.1000040b8

# Print the disassembly of the function
pdf
