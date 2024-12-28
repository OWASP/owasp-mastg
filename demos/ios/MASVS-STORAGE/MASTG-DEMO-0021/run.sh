#!/bin/bash
python3 ./fridump.py -U -s MASTestApp
cat dump/strings.txt > output.txt
