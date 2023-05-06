import re, os
from pathlib import Path
from typing import List
from dataclasses import dataclass
import yaml

EMOJIS_regex = r"🥇 |🎁 |📝 |❗ "

@dataclass
class MarkdownLink:
    raw: str
    text: str
    url: str
    external: bool
    title: str = ""
    raw_new: str = ""

def extract_markdown_links(md_file_content: str) -> List[MarkdownLink]:
    md_links = []
    
    for match in re.finditer(r'\[([^\]]+)\]\(([^ ")]+)(?: "([^"]+)")?\)', md_file_content):
        # raw is the full match
        raw = match.group(0)
        text = match.group(1)
        url = match.group(2)
        title = match.group(3).strip('"') if match.group(3) is not None else ""
        external = True if url.startswith("http") else False
        
        raw_new = ""
        if not external:
            directory = ""
            if "0x01" in raw or "0x02" in raw or "0x03" in raw:
                directory = "/MASTG/Intro/"
            elif "0x04" in raw:
                directory = "/MASTG/General/"
            elif "0x05" in raw:
                directory = "/MASTG/Android/"
            elif "0x06" in raw:
                directory = "/MASTG/iOS/"
            elif "0x08" in raw:
                directory = "/MASTG/Tools/"
            elif "0x09" in raw:
                directory = "/MASTG/References/"
            else:
                continue
            
            if "Document/" in raw:
                raw_new = re.sub(r"\.\./\.\./\.\./Document/", directory, raw)
            else:
                full_url = f"{directory}{url}"
                if title != "":
                    full_url = f'{full_url} "{title}"'
                raw_new = f"[{text}]({full_url})"
            
            raw_new = re.sub(r"\.md", "", raw_new)

        md_links.append(MarkdownLink(raw, text, url, external, title, raw_new))
    return md_links

# def transform_links(file_text):
#     # print("[*] Regex Substitutions ../Document to MASTG/")
#     found = re.findall(r'(\(.*/+0x.*\.md/*)', file_text)

#     # TODO FIX we must find a better solution to this
#     while len(found) > 0:
#         print(f"    Found: {found}")
#         file_text = re.sub(r"\(.*/+(0x0[1-3].*\.md)", r"(../Intro/\1", file_text)
#         file_text = re.sub(r"\(.*/+(0x04.*\.md)", r"(../General/\1", file_text)
#         file_text = re.sub(r"\(.*/+(0x05.*\.md)", r"(../Android/\1", file_text)
#         file_text = re.sub(r"\(.*/+(0x06.*\.md)", r"(../iOS/\1", file_text)
#         file_text = re.sub(r"\(.*/+(0x08.*\.md)", r"(../Tools/\1", file_text)
#         file_text = re.sub(r"\(.*/+(0x09.*\.md)", r"(../References/\1", file_text)

#         found = re.findall(r'(\(.*/+0x.*\.md/*)', file_text)

#     return file_text

def remove_emojis(file_text):
    print("[*] Regex Substitutions for emojis")
    found = re.findall(EMOJIS_regex, file_text)
    print(f"    Found: {found}")
    return re.sub(EMOJIS_regex, r"", file_text)

def transform(folder):
    print(f"[*] Applying transforms to {folder}")
    # links_dict = {}
    for root, dirname, filenames in os.walk(folder):
        if len(filenames):
            files = Path(root).glob('*.md')
            for file in files:
                file_text = file.read_text()
                
                links = extract_markdown_links(file_text)
                # relative_path = file.relative_to(".").as_posix()
                # links_dict[relative_path] = [link.__dict__ for link in links if link.external is False]

                internal_links = []
                external_links = []
                new_text = file_text  # start with the original file text
                for link in links:
                    if link.external is False:
                        new_text = new_text.replace(link.raw, link.raw_new)
                        internal_links.append(link.raw_new)
                    else:
                        external_links.append(link.raw)

                resources_section = ""
                
                if len(internal_links) > 0:
                    internal_links = sorted(list(set(internal_links)))
                    # add - to each link
                    internal_links = [f"- {link}" for link in internal_links]
                    
                    internal_links_text = "\n".join(internal_links)
                    internal_links_text = f"\n\n### Internal\n\n{internal_links_text}"
                    resources_section += internal_links_text

                # if len(external_links) > 0:
                #     external_links = sorted(list(set(external_links)))
                #     # add - to each link
                #     external_links = [f"- {link}" for link in external_links]

                #     external_links_text = "\n".join(external_links)
                #     external_links_text = f"\n\n### External\n\n{external_links_text}"
                #     resources_section += external_links_text
                if resources_section != "":
                    new_text += "\n## Resources" + resources_section + "\n"
                file.write_text(new_text) 

                # file_obj = Path(file)
                # print(f"    - File {file_obj.as_posix()}")
                # file_text = file_obj.read_text()
                
                # new_text = None
                # for function in functions:
                #     if new_text is None:
                #         new_text = function(file_text)
                #     else:
                #         new_text = function(new_text)

                # file_obj.write_text(new_text)

transform("docs/MASTG")

# transform("docs/MASTG", [transform_links])
# transform("docs/MASTG", [remove_emojis])