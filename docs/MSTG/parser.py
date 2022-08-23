import re
import os
import yaml
from pathlib import Path


def parse_content_and_header(value):
    regex = r'\n## [a-zA-Z ]+\n' # finds headers for the current i
    content = re.split(regex, value)
    content = content[1:]
    regex = r'\n## ([a-zA-Z ]+)\n' # finds headers for the current i
    headers = re.findall(regex, value)
    return { 'content': content, 'headers': headers }

def get_content(file):
    file_text = Path(file).read_text()
    return parse_content_and_header(file_text)

def get_frontmatter(file):
    frontmatter = None
    with open(file) as f:
        frontmatter = next(yaml.load_all(f, Loader=yaml.FullLoader))
    return dict(frontmatter)

for folder in ["/Users/carlos/Desktop/owasp-mstg/docs/MSTG/android", "/Users/carlos/Desktop/owasp-mstg/docs/MSTG/ios"]:
    for root, dirname, filenames in os.walk(folder):
        if len(filenames):
            files = Path(root).glob('*.md')
            for file in files:
                if file.name != "overview.md":
                    print(file.name)

                    frontmatter = get_frontmatter(file)
                    result = get_content(file)

                    headers = result['headers']
                    content = result['content']

                    the_dict = {}
                    for i, header in enumerate(headers):
                        key = header.strip().lower().replace(" ", "_")
                        the_dict[key] = content[i]
                    
                    print(the_dict.keys())
                    # print(yaml.dump(the_dict, indent=4))
