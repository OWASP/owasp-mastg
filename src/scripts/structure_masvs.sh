#!/bin/bash

if [ ! -d "../owasp-masvs/" ] ; then
  echo "Error: Clone owasp-masvs to same directory as owasp-mastg: cd .. && git clone https://github.com/OWASP/owasp-masvs.git"
  exit 1
fi

cp ../owasp-masvs/Document/*-*.md docs/MASVS/
cp ../owasp-masvs/controls/ docs/MASVS/

if [[ "$(uname)" == "Darwin" ]]; then
    SED="gsed"
else
    SED="sed"
fi

mkdir -p docs/assets/Images/MASVS
cp ../owasp-masvs/Document/images/* docs/assets/Images/MASVS
$SED -i "s#images/#../../../assets/Images/MASVS/#g" docs/MASVS/**/*.md
$SED -i "s#images/#../../assets/Images/MASVS/#g" docs/MASVS/*.md