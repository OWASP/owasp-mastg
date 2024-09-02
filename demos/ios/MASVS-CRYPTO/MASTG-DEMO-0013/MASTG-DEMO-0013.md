---
platform: ios
title: Use of Hardcoded RSA Private Key in SecKeyCreateWithData with r2
code: [swift]
id: MASTG-DEMO-0013
test: MASTG-TEST-0216
---

### Sample

{{ MastgTest.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Open the app binary with @MASTG-TOOL-0073 with the `-i` option to run this script.

{{ sec_hardcoded_rsa.r2 }}

{{ run.sh }}

### Observation

The output reveals the hardcoded RSA private key within the binary. This key is typically found in the DATA section of the binary, where it is loaded into memory for cryptographic operations. The presence of hardcoded keys can be identified by searching for sequences of bytes or strings corresponding to the key.

{{ output.txt # function.txt # key.txt }}

Identify where the x0 register, which holds the key data, is populated before the call to `SecKeyCreateWithData`. Trace back through the instructions to find where x0 comes from:

```asm
│           0x100004b74      mov x0, x20
│           0x100004b78      mov x1, x21
│           0x100004b7c      bl sym.imp.SecKeyCreateWithData
```

Look for `ldr`, `ldp`, `adrp`, and `add` instructions, which are often used to load data from memory or set up addresses.

```asm
│           0x100004998      adrp x0, segment.__DATA                   ; 0x100010000
│           0x10000499c      add x0, x0, 0x328                         ; int64_t arg1
```

This seems to be the source of the data in `x0`. Check for earlier function calls or memory loading instructions.

In this case data is loaded from `segment.__DATA` (0x100010000), let's inspect those memory regions:

```asm
[0x100004c84]> s 0x100010000
[0x100010000]> px 256
- offset -    0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x100010000  8100 0000 2800 0000 2800 0000 0000 0000  ....(...(.......
0x100010010  0000 0000 0000 0000 5086 0000 0000 9000  ........P.......
0x100010020  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x100010030  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x100010040  0000 0000 0000 0000 8000 0000 1000 0000  ................
0x100010050  1000 0000 0000 0000 0000 0000 0000 0000  ................
0x100010060  5086 0000 0000 6000 0000 0000 0000 0000  P.....`.........
0x100010070  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x100010080  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x100010090  7888 0000 0000 1000 bb00 0000 0000 7088  x.............p.
0x1000100a0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x1000100b0  0000 0000 0000 0000 5f02 0000 0000 0000  ........_.......
0x1000100c0  be04 0000 0000 0000 3082 025b 0201 0002  ........0..[....
0x1000100d0  8181 00bd f689 8fbd 0ce6 4f9a 97ec 301a  ..........O...0.
0x1000100e0  4893 4d2a bfdf f708 154c db87 e5df b1cf  H.M*.....L......
0x1000100f0  8da2 5e2a 7d92 a8bd 30b9 10cf 96da 1025  ..^*}...0......%
```

RSA keys have specific patterns, especially when encoded in ASN.1/DER format. You can search for common byte patterns like 0x30 0x82 (which indicates the start of a DER sequence). You can also use r2 search capabilities to find such patterns:

```asm
[0x100007430]> e search.from = 0x1000100a0
[0x100007430]> e search.to = 0x1000100a0 + 0x4c8
[0x100007430]> /x 3082
0x1000100c8 hit4_0 3082
```

There is only one hit for the 0x30 0x82 pattern within `segment.__DATA`. You can use the `px` command to print all the bytes from the RSA key. The total length of the encoded key is the length of the sequence plus the length of the initial identifier and length fields.

The total length of the encoded key is calculated as:

- 1 byte for 0x30 (SEQUENCE identifier)
- 1 byte for 0x82 (indicating long-form length)
- 2 bytes for 0x025b (length of the sequence)
- 603 bytes for the sequence itself

So, the total length is: 1 + 1 + 2 + 603 = 607 bytes

{{ key.txt }}

Note that it seems that we could not find this address in the disassembly, but if you recall, the very first reference to `segment.__DATA` we had was:

```asm
│           0x100004998      adrp x0, segment.__DATA                   ; 0x100010000
│           0x10000499c      add x0, x0, 0x328                         ; int64_t arg1
```

And this is pointing to 0x100010000 + 0x328 = 0x100010328, which is exactly after the RSA key which goes from 0x1000100c8 to 0x10001327. So, the key must be held within some data structure which must be the one being loaded into memory and then passed to `SecKeyCreateWithData`.

The length of the actual key can be obtained from the length of the modulus (n) in the RSA key. The modulus is the first integer in the RSA key, and its length is the key size. In this case, we see `0002 8181 00bd f689 ...`. In DER the length of the modulus is encoded as `02 81 81`, where:

- `02` is the INTEGER tag, indicating that the following bytes represent an integer (in this case, the modulus).
- the first `81` indicates that the length of the data (the modulus) is provided in the next byte.
- the second `81` indicates that the length of the modulus is 129 bytes long including the `00` byte which is added to force the integer to be positive. The key size is calculated as `(0x81 - 1) * 8 = 128 * 8 = 1024 bits`.

If you want to decode the key you can use this website: [https://lapo.it/asn1js/](https://lapo.it/asn1js/) which is going to decode it as:

```txt
RSAPrivateKey SEQUENCE (9 elem)
    version Version INTEGER 0
    modulus INTEGER (1024 bit) 133396580715800090592469243143215418884374307199930301828108855519157…
    publicExponent INTEGER 65537
...
```

You can hover over the different parts of the key to see the decoded values in hex on the right side of the screen.

### Evaluation

The test fails because a hardcoded RSA private key was found in the code.
