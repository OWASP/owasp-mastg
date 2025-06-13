#!/bin/bash

# ./src/scripts/structure_masvs.sh
./src/scripts/structure_mastg.sh
IGNORE_LAST_COMMIT_DATE=1 GITHUB_TOKEN=xx  mkdocs serve -a localhost:8000  --dirtyreload
