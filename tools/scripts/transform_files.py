import re, os
from pathlib import Path

EMOJIS_regex = r"🥇|🎁|📝|❗"

def transform_links():
    print("[*] Regex Substitutions ../Document to MASTG/")
    found = re.findall(r'(\((?:../)*Document/.*\.md/*)', file_text)
    print(f"    Found: {found}")
    return re.sub(r"\(((?:../)*)Document/(.*)\.md/*",r"(\1MASTG/\2/", file_text)

def remove_emojis():
    print("[*] Regex Substitutions for emojis")
    found = re.findall(EMOJIS_regex, file_text)
    print(f"    Found: {found}")
    return re.sub(EMOJIS_regex,r"", file_text)

for root, dirname, filenames in os.walk("docs"):
    if len(filenames):
        files = Path(root).glob('*.md')

        for file in files:
            file_obj = Path(file)
            print(f"    - File {file_obj.as_posix()}")
            file_text = file_obj.read_text()
            
            new_text = remove_emojis()
            new_text = transform_links(new_text)

            file_obj.write_text(new_text)
            