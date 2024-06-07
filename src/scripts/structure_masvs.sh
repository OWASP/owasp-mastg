mkdir docs/MASVS
mkdir docs/MASVS/Intro
mkdir docs/MASVS/controls
cp owasp-masvs/Document/*.md docs/MASVS
mv docs/MASVS/0[1-4]*.md docs/MASVS/Intro
mv owasp-masvs/controls/* docs/MASVS/controls

mkdir docs/assets/Images/MASVS
mv owasp-masvs/Document/images/* docs/assets/Images/MASVS
sed -i "s#images/#../../../assets/Images/MASVS/#g" docs/MASVS/**/*.md
sed -i "s#images/#../../assets/Images/MASVS/#g" docs/MASVS/*.md