#!/bin/sh
cd $TRAVIS_BUILD_DIR/Tools
sh ./gitbookepubandpdf.sh $TRAVIS_TAG
sh ./generate_document.sh
