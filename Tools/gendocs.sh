#!/bin/sh
cd $TRAVIS_BUILD_DIR/Tools
npm install
pwd
node genpdf.js -tag $TRAVIS_TAG -relnotes "Fist automated version since 1.0"
sh ./generate_document.sh
