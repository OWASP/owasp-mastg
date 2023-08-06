rm -rf docs/MASTG
./src/scripts/structure_mastg.sh
python3 src/scripts/transform_files.py
python3 src/scripts/populate_dynamic_pages.py
python3 src/scripts/generate_redirects.py