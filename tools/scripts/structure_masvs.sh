mkdir docs/MASVS
mkdir docs/MASVS/Intro
mkdir docs/MASVS/Controls
mkdir docs/MASVS/Appendix
cp owasp-masvs/Document-es/0x*.md docs/MASVS
mv docs/MASVS/0x0[1-4]*.md docs/MASVS/Intro
mv docs/MASVS/0x*V[1-8]*.md docs/MASVS/Controls
mv docs/MASVS/0x9*.md docs/MASVS/Appendix