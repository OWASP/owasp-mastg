#!/bin/bash
set -ev

if [ -z "$TRAVIS_TAG" ]; then 
npm install -g markdownlint-cli
npm install -g markdown-link-check
fi
npm install -g gitbook-cli
gem install asciidoctor
brew install pandoc
brew cask install calibre
brew install epubcheck
brew install gnu-sed
