import pandas
import yaml
import requests
from pathlib import Path

def dict_to_md(data, column_titles=None):
    if column_titles is None: column_titles = {key:key.title() for (key,_) in data[0].items()}
    df = pandas.DataFrame.from_dict(data).rename(columns=column_titles)
    return df.to_markdown(index=False)

def append_to_file(new_content, file_path):
    file = Path(file_path)
    content = file.read_text() + new_content
    file.write_text(content)

# talks.md

data = yaml.safe_load(open("docs/assets/data/talks.yaml"))

for element in data:
    if element['video'].startswith("http"):
        element['video'] = f"[:octicons-play-24: Video]({element['video']})"
    if element['slides'].startswith("http"):
        element['slides'] = f"[:material-file-presentation-box: Slides]({element['slides']})"

append_to_file(dict_to_md(data) + "\n\n<br>\n", "docs/talks.md")

# contributors.md

data = yaml.safe_load(open("docs/assets/data/contributors.yaml"))
append_to_file(dict_to_md(data) + "\n\n<br>\n", "docs/contributors.md")


# checklists.md

masvs_full_en = requests.get("https://github.com/OWASP/owasp-mastg/releases/latest/download/masvs_full_en.yaml", stream=True)
data = yaml.safe_load(masvs_full_en.raw)
data_list = []
for _, value in data.items():
    
    # levels
    value['L1'] = "<span class='mas-dot-blue'></span>" if value['L1'] == True else ""
    value['L2'] = "<span class='mas-dot-green'></span>" if value['L2'] == True else ""
    value['R'] = "<span class='mas-dot-orange'></span>" if value['R'] == True else ""

    # tests
    value["common"] = ""
    value["android"] = ""
    value["ios"] = ""
    if links:=value.get("links"):
        for link in value.get("links"):
            value["common"] += f"[Test Case]({link})<br>" if "0x04" in link else ""
            value["android"] += f"[Test Case]({link})<br>" if "0x05" in link else ""
            value["ios"] += f"[Test Case]({link})<br>" if "0x06" in link else ""
        del value["links"]
    data_list.append(value)

append_to_file("\n<br>\n\n" + dict_to_md(data_list) + "\n\n<br>\n", "docs/MAS_checklist.md")
