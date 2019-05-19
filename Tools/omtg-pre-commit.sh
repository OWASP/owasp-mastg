#!/bin/sh
# Add this to .git/hooks/pre-commit to auto-update the TOC with each commit.

PROJECT_PATH="PATH_TO_OMTG_GIT_REPO"

echo "Generating TOC..."

pushd $PROJECT_PATH/Tools > /dev/null

./generate_toc.rb > $PROJECT_PATH/Generated/OWASP-MSTG-Table-of-Contents.html

popd > /dev/null
