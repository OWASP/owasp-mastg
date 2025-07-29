#!/bin/bash

jq '
  select(
    .class=="android.security.keystore.KeyGenParameterSpec$Builder"
    and .method=="setBlockModes"
    and (.inputParameters[0].value | contains(["ECB"]))
  )
' output.json