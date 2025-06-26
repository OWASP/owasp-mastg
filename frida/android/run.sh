#!/bin/bash

hookPath=$1
hook=$(cat "$hookPath")
decoderScript=$(cat "$(dirname "$0")"/decoder.js)
fridaScript=$(cat "$(dirname "$0")"/run.js)

{
  echo "$hook"
  echo $'\n'
  echo "$decoderScript"
  echo $'\n'
  echo "$fridaScript"
}  > /tmp/frida_script.js

frida -U -f org.owasp.mastestapp -l /tmp/frida_script.js -o output.txt

