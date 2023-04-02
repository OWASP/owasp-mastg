import pandas
import yaml
import os
from pathlib import Path
import combine_data_for_checklist

# checklist functions

def get_platform_icon(platform):
    if platform == "android":
        return '<span style="font-size: large; color: darkgrey;"> :material-android: </span>'
    elif platform == "ios":
        return '<span style="font-size: large; color: darkgrey;"> :material-apple: </span>'
    elif platform == "general":
        return '<span style="font-size: large; color: darkgrey;"> :material-asterisk: </span>'

def get_level_icon(level, value):
    if level == "L1" and value == True:
        return '<span class="mas-dot-blue"></span>'
    elif level == "L2" and value == True:
        return '<span class="mas-dot-green"></span>'
    elif level == "R" and value == True:
        return '<span class="mas-dot-orange"></span>'

def set_icons_for_web(checklist):
    for row in checklist:
        # if it's a control row, make the MASVS-ID and Control bold
        if row['MASVS-ID'] != "":
            row['MASVS-ID'] = f"**[{row['MASVS-ID']}]({row['path']})**"
            row['Control / MASTG Test'] = f"**{row['Control / MASTG Test']}**"
        # if it's a test row, set the icons for platform and levels
        else:
            row['Platform'] = get_platform_icon(row['Platform'])
            row['Control / MASTG Test'] = f"[{row['Control / MASTG Test']}]({row['path']})"
            row['L1'] = get_level_icon('L1', row['L1'])
            row['L2'] = get_level_icon('L2', row['L2'])
            row['R'] = get_level_icon('R', row['R'])
        
        del row['path']

def dict_to_md(data, column_titles=None, column_align=None):
    if column_titles is None: column_titles = {key:key.title() for (key,_) in data[0].items()}
    df = pandas.DataFrame.from_dict(data).rename(columns=column_titles)
    return df.to_markdown(index=False, colalign=column_align)

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

# checklists.md

CHECKLISTS_DIR = "checklists"

checklist_dict = combine_data_for_checklist.get_checklist_dict()

column_titles = {'MASVS-ID': 'MASVS-ID', 'Platform': "Platform", 'Control / MASTG Test': 'Control / MASTG Test', 'L1': 'L1', 'L2': 'L2', 'R': 'R'}
column_align=("left", "center", "left", "center", "center", "center")

if not os.path.exists(CHECKLISTS_DIR):
    os.mkdir(CHECKLISTS_DIR)

for group_id, checklist in checklist_dict.items():
    set_icons_for_web(checklist)
    content = dict_to_md(checklist, column_titles, column_align) + "\n\n<br><br>"

    with open(f"docs/{CHECKLISTS_DIR}/{group_id}.md", 'w') as f:
        f.write(content)
