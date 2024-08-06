#!/bin/bash

./src/scripts/structure_masvs.sh
./src/scripts/structure_mastg.sh
mkdocs serve -a localhost:8000
