#!/bin/sh
cd $TRAVIS_BUILD_DIR/Tools
echo "Applying Link check"
sh ./Apply_Link_Check.sh
echo "Applying Linter check"
sh ./Apply_Linter_Check.sh
echo "Counting amount of linter issues:"
wc -l ../linter-result.out

if [ -z "$TRAVIS_TAG" ]; then 
exit 0; 
fi
echo "Running creaton of pdfs and word documents"
sh ./gitbookepubandpdf.sh $TRAVIS_TAG
sh ./generate_document.sh
