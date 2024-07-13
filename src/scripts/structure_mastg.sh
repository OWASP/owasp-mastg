#!/bin/bash

cp -r tests docs/MASTG/
cp -r techniques docs/MASTG/
cp -r tools docs/MASTG/
cp -r apps docs/MASTG/
cp -r weaknesses/** docs/MASWE/
cp -r tests-beta docs/MASTG/
cp -r demos docs/MASTG/
cp -r rules docs/MASTG/

cp -r Document/0x0*.md docs/MASTG
cp docs/MASTG/0x08b-Reference-Apps.md docs/MASTG/apps/index.md
cp docs/MASTG/0x08a-Testing-Tools.md docs/MASTG/tools/index.md

cp Document/tests.md docs/MASTG/tests/index.md
cp Document/techniques.md docs/MASTG/techniques/index.md

if [[ "$(uname)" == "Darwin" ]]; then
    SED="gsed"
else
    SED="sed"
fi

cp -r Document/Images/ docs/assets/Images/
find docs/MASTG/tests -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../../../assets/Images/#g' {} \;
find docs/MASTG/techniques -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../../../assets/Images/#g' {} \;
find docs/MASTG/tools -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../../../assets/Images/#g' {} \;
find docs/MASTG/apps -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../../../assets/Images/#g' {} \;
find docs/MASTG -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../assets/Images/#g' {} \;

