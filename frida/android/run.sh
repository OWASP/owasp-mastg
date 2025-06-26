#!/bin/bash

hookPath=$1
hook=$(cat "$hookPath")
decoderScript=$(cat "$(dirname "$0")"/decoder.js)
fridaScript=$(cat "$(dirname "$0")"/run.js)
randomNumber=$RANDOM

{
  echo "$hook"
  echo $'\n'
  echo "$decoderScript"
  echo $'\n'
  echo "$fridaScript"
}  > /tmp/frida_script_$randomNumber.js

frida -U -f org.owasp.mastestapp -l /tmp/frida_script_$randomNumber.js -o output.txt

# cleanup
rm /tmp/frida_script_$randomNumber.js