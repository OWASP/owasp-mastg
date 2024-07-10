import os
import re
from pathlib import Path
from typing import List
import yaml
from dataclasses import dataclass
import git_data

EMOJIS_regex = r"🥇 |🎁 |📝 |❗ "

@dataclass
class MarkdownLink:
    raw: str
    text: str
    url: str
    external: bool
    title: str = ""
    raw_new: str = ""


def remove_emojis(file_text):
    print("[*] Regex Substitutions for emojis")
    found = re.findall(EMOJIS_regex, file_text)
    print(f"    Found: {found}")
    return re.sub(EMOJIS_regex, r"", file_text)

def update_yaml_frontmatter(file_text, last_updated):
    """
    Updates the YAML frontmatter with the tools and examples list.
    """
    # Regular expression to match the YAML frontmatter at the beginning of the file
    frontmatter_pattern = r'^---\n(.*?)\n---\n'
    match = re.search(frontmatter_pattern, file_text, re.DOTALL)
    
    if match:
        frontmatter_str = match.group(1)
        frontmatter = yaml.safe_load(frontmatter_str)

        frontmatter["last_updated"] = last_updated

        # Replace the old frontmatter with the updated frontmatter
        updated_frontmatter = f"---\n{yaml.dump(frontmatter, indent=4, sort_keys=False)}---\n"
        file_text = file_text.replace(match.group(0), updated_frontmatter, 1)

    return file_text


def update_frontmatter_list(current_list, new_items):
    """
    Updates a list in the frontmatter with new items.
    """
    updated_list = current_list + new_items
    return sorted(list(set(updated_list)))

def process_markdown_files(folder):
    """
    Processes all markdown files in the given folder.
    """
    for root, _, filenames in os.walk(folder):
        if filenames:
            markdown_files = Path(root).glob('*.md')

            for markdown_file in markdown_files:
                if markdown_file.name == "index.md":
                    continue
                file_content = markdown_file.read_text()

                last_updated = git_data.get_last_commit_date(Path(markdown_file.as_posix().replace('docs/MASTG', '.')).absolute().as_posix())

                updated_content = update_yaml_frontmatter(file_content, last_updated)
                markdown_file.write_text(updated_content)


process_markdown_files("docs/MASTG")