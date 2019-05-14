#!/bin/sh
cd $TRAVIS_BUILD_DIR/Tools
echo "Applying Link check"
sh ./Apply_Link_Check.sh
echo "Applying Linter check"
sh ./Apply_Linter_Check.sh
sh ./gitbookepubandpdf.sh $TRAVIS_TAG
sh ./generate_document.sh
