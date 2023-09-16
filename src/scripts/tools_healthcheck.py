import os
import re
import yaml

def extract_frontmatter(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            frontmatter = next(yaml.safe_load_all(f)) or {}
    except (UnicodeDecodeError, yaml.reader.ReaderError):
        # Try to read with 'ISO-8859-1' if 'utf-8' fails
        try:
            with open(file_path, 'r', encoding='ISO-8859-1') as f:
                frontmatter = next(yaml.safe_load_all(f)) or {}
        except Exception:
            print(f"Skipped problematic file: {file_path}")
            frontmatter = {}

    return frontmatter

# Walk through the extracted files and extract the YAML frontmatter
file_paths = [os.path.join(root, file) for root, dirs, files in os.walk('tools') for file in files if file.endswith('.md')]

# Filter out '__MACOSX' files
file_paths = [file_path for file_path in file_paths if '__MACOSX' not in file_path]

# Extract the YAML frontmatter again
frontmatters = [extract_frontmatter(file_path) for file_path in file_paths]

# Create the markdown table
table = '| name | platform | link | release | commit |\n| --- | --- | --- | --- | --- |\n'
for frontmatter in frontmatters:
    name = frontmatter.get('title', '')
    platform = frontmatter.get('platform', '')
    source = frontmatter.get('source', '')
    github_link = source if 'github.com' in source else ''
    if github_link:
        user, repo = re.search(r"github.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", github_link).groups()
        release = f'![GitHub Release Date - Published_At](https://img.shields.io/github/release-date/{user}/{repo}?style=for-the-badge&label=LAST%20RELEASE)'
        commit = f'![GitHub last commit (branch)](https://img.shields.io/github/last-commit/{user}/{repo}/master?style=for-the-badge)'
    else:
        release = ''
        commit = ''
    table += f'| {name} | {platform} | {github_link} | {release} | {commit} |\n'

# Save the markdown file
with open('Tools_Health_Check.md', 'w') as f:
    f.write(f'# Tools Health Check\n\n{table}')
