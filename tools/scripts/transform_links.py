import re, os
from pathlib import Path

print("[*] Regex Substitutions ../Document to MASTG/")

for root, dirname, filenames in os.walk("docs"):
    if len(filenames):
        files = Path(root).glob('*.md')

        for file in files:
            file_obj = Path(file)
            print(f"    - File {file_obj.as_posix()}")
            file_text = file_obj.read_text()
            found = re.findall(r'(\((?:../)*Document/.*\.md/*)', file_text)
            print(f"    Found: {found}")
            new_text = re.sub(r"\((?:../)*Document/(.*)\.md/*",r"(MASTG/\1/", file_text)
            file_obj.write_text(new_text)