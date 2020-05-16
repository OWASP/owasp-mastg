#!/bin/sh
cd $TRAVIS_BUILD_DIR/Tools
echo "Applying Linter check"
sh ./Apply_Linter_Check.sh
echo "Counting amount of linter issues:"
export RESULT=$(wc -l ../linter-result.out)
echo $RESULT
echo "Applying Link check"
sh ./Apply_Link_Check.sh
echo "Running creaton of pdfs and word documents"
sh ./gitbookepubandpdf.sh "TST-LOCAL"
sh ./generate_document.sh
