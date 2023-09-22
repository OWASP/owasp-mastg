mkdir docs/MASTG
mkdir docs/MASTG/Intro      
mkdir docs/MASTG/General
mkdir docs/MASTG/Android
mkdir docs/MASTG/iOS
mkdir docs/MASTG/References

cp Document/tests.md docs/MASTG
cp Document/0x08b-Reference-Apps.md docs/MASTG/apps.md
cp Document/0x08a-Testing-Tools.md docs/MASTG/tools.md
cp Document/techniques.md docs/MASTG

cp Document/0x0[1-6]*.md docs/MASTG
cp -r tests docs/MASTG/
cp -r techniques docs/MASTG/
cp -r tools docs/MASTG/
cp -r apps docs/MASTG/

mv docs/MASTG/0x0[1-3]*.md docs/MASTG/Intro
mv docs/MASTG/0x04*.md docs/MASTG/General
mv docs/MASTG/0x05*.md docs/MASTG/Android
mv docs/MASTG/0x06*.md docs/MASTG/iOS
mv docs/MASTG/0x09*.md docs/MASTG/References