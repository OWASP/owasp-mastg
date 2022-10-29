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
    if element['video'].startswith("https://"):
        element['video'] = f"[:octicons-play-24: Video]({element['video']})"
    if element['slides'].startswith("https://"):
        element['slides'] = f"[:material-file-presentation-box: Slides]({element['slides']})"

append_to_file(dict_to_md(data) + "\n\n<br>\n", "docs/talks.md")

# checklists.md

masvs_full_en = requests.get("https://github.com/OWASP/owasp-mastg/releases/latest/download/masvs_full_en.yaml", stream=True)
data = yaml.safe_load(masvs_full_en.raw)
data_list = []
for _, value in data.items():
    if links:=value.get("links"):
        value["links"] = " ".join([f"[Test Case]({link})" for link in links])
    else:
        value["links"] = "N/A"
    data_list.append(value)
append_to_file("\n<br>\n\n" + dict_to_md(data_list) + "\n\n<br>\n", "docs/MAS_checklist.md")
