#!/bin/bash
set -ev

if [ -z "$TRAVIS_TAG" ]; then 
exit 0; 
fi
brew install pandoc
brew cask install calibre
brew install epubcheck
brew install gnu-sed
