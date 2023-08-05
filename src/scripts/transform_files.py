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

def remove_emojis(file_text):
    print("[*] Regex Substitutions for emojis")
    found = re.findall(EMOJIS_regex, file_text)
    print(f"    Found: {found}")
    return re.sub(EMOJIS_regex, r"", file_text)

def add_resources_section(file_text, links):
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

    if resources_section != "":
        new_text += "\n## Resources" + resources_section + "\n"
    
    return new_text

def get_tools_links(links):
    """
    tools are tool apps links like [UnCrackable App for Android Level 4: Radare2 Pay](0x08a-Testing-Tools.md#android-uncrackable-l4) or [UnCrackable App for Android Level 4: Radare2 Pay](0x08b-Reference-Apps.md#android-uncrackable-l4 "Uncrykable App for Android Level 4: Radare2 Pay")
    This function iterates links to build a unique list of tools (the text after the anchor)
    """
    tools = []
    for link in links:
        if link.external is False:
            if "#" in link.raw:
                if "0x08a" in link.raw:
                    # get tool-name with regex considering that it might be [text](some.md#tool-name) or [text](some.md#tool-name "title"), the whitespace might be there or not
                    match = re.search(r"\#([^ \")]*)(?=\s|\)|$)", link.raw)
                    if match:
                        tool_name = match.group(1)
                        tools.append(tool_name)
    tools = sorted(list(set(tools)))
    return tools


def get_examples_links(links):
    """
    Examples are example apps links like [UnCrackable App for Android Level 4: Radare2 Pay](0x08b-Reference-Apps.md#android-uncrackable-l4) or [UnCrackable App for Android Level 4: Radare2 Pay](0x08b-Reference-Apps.md#android-uncrackable-l4 "Uncrykable App for Android Level 4: Radare2 Pay")
    This function iterates links to build a unique list of examples (the text after the anchor)
    """
    examples = []
    for link in links:
        if link.external is False:
            if "#" in link.raw:
                if "0x08b" in link.raw:
                    # get example-name with regex considering that it might be [text](some.md#example-name) or [text](some.md#example-name "title"), the whitespace might be there or not
                    match = re.search(r"\#([^ \")]*)(?=\s|\)|$)", link.raw)
                    if match:
                        example_name = match.group(1)
                        examples.append(example_name)
    examples = sorted(list(set(examples)))
    return examples

def update_yaml_frontmatter(file_text, tools, examples):
    """
    This function updates the yaml frontmatter with the tools and examples list
    """
    if '---\n' in file_text:
        parts = file_text.split('---\n', 2)  # split the file at the second '---'
        yaml_dict = yaml.load(parts[1], Loader=yaml.FullLoader)
        
        if type(yaml_dict) is dict:
            # read current values of tools and examples, if existing, and update them with the new ones, ensuring uniqueness
            tools_current = yaml_dict.get("tools", [])
            examples_current = yaml_dict.get("examples", [])
            tools = sorted(list(set(tools_current + tools)))
            examples = sorted(list(set(examples_current + examples)))
            yaml_dict["tools"] = tools
            yaml_dict["examples"] = examples

            yaml_frontmatter_new = yaml.dump(yaml_dict, indent=4, sort_keys=False)
            file_text_new = f"---\n{yaml_frontmatter_new}---\n{parts[2]}"  # join the parts back together
            return file_text_new
        else:
            return file_text
    else:
        return file_text

def transform(folder):
    print(f"[*] Applying transforms to {folder}")

    for root, dirname, filenames in os.walk(folder):
        if len(filenames):
            files = Path(root).glob('*.md')
            for file in files:
                file_text = file.read_text()
                
                links = extract_markdown_links(file_text)
              
                # new_text = add_resources_section(file_text, links)
                new_text = file_text

                tools = get_tools_links(links)
                examples = get_examples_links(links)
                new_text = update_yaml_frontmatter(new_text, tools, examples)
                
                file.write_text(new_text) 

# transform("docs/MASTG")
transform("docs/MASTG/techniques")
transform("docs/MASTG/tools")
transform("docs/MASTG/apps")
