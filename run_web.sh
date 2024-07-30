#!/bin/bash

./src/scripts/structure_masvs.sh
./src/scripts/structure_mastg.sh
mkdocs serve -a 0.0.0.0:8000
