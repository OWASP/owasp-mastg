#!/bin/bash

if [ -d "../maswe/" ] ; then
    MASWE_DIR=../maswe
elif [ -d "./maswe/" ] ; then
    MASWE_DIR=./maswe
else
    echo "Error: Please clone maswe to same directory as mastg: cd .. && git clone https://github.com/OWASP/maswe.git"
    exit 1
fi

cp -r $MASWE_DIR/weaknesses/ weaknesses/
