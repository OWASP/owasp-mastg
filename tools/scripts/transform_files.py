import re, os
from pathlib import Path

EMOJIS_regex = r"🥇 |🎁 |📝 |❗ "

def transform_links(file_text):
    print("[*] Regex Substitutions ../Document to MASTG/")
    found = re.findall(r'(\(0x.*\.md/*)', file_text)
    print(f"    Found: {found}")

    file_text = re.sub(r"\(0x0[1-3].*)\.md/*", r"(../Intro/\1/", file_text)
    file_text = re.sub(r"\(0x04.*)\.md/*", r"(../General/\1/", file_text)
    file_text = re.sub(r"\(0x05.*)\.md/*", r"(../Android/\1/", file_text)
    file_text = re.sub(r"\(0x06.*)\.md/*", r"(../iOS/\1/", file_text)
    file_text = re.sub(r"\(0x08.*)\.md/*", r"(../\1/", file_text)
    file_text = re.sub(r"\(0x09.*)\.md/*", r"(../References/\1/", file_text)

    return file_text

def remove_emojis(file_text):
    print("[*] Regex Substitutions for emojis")
    found = re.findall(EMOJIS_regex, file_text)
    print(f"    Found: {found}")
    return re.sub(EMOJIS_regex, r"", file_text)

def transform(folder, functions):
    print(f"[*] Applying transforms to {folder}")
    for root, dirname, filenames in os.walk(folder):
        if len(filenames):
            files = Path(root).glob('*.md')

            for file in files:
                file_obj = Path(file)
                print(f"    - File {file_obj.as_posix()}")
                file_text = file_obj.read_text()
                
                new_text = None
                for function in functions:
                    if new_text is None:
                        new_text = function(file_text)
                    else:
                        new_text = function(new_text)

                file_obj.write_text(new_text)

transform("docs", [transform_links])
transform("Document", [remove_emojis])