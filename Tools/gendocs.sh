#!/bin/sh
cd $TRAVIS_BUILD_DIR/Tools
npm install
pwd
node genpdf.js
sh ./generate_document.sh
