mkdir docs/MASVS
mkdir docs/MASVS/Intro
mkdir docs/MASVS/controls
cp owasp-masvs/Document/*.md docs/MASVS
mv docs/MASVS/0[1-4]*.md docs/MASVS/Intro
mv owasp-masvs/controls/* docs/MASVS/controls