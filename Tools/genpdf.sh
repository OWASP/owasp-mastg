#!/bin/sh
cd $TRAVIS_BUILD_DIR/Tools
npm install
node genpdf.js
