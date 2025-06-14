#!/bin/bash

./src/scripts/structure_masvs.sh
./src/scripts/structure_mastg.sh
IGNORE_LAST_COMMIT_DATE=1 mkdocs serve -a localhost:8000  # --dirtyreload
