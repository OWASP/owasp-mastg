import pandas
import yaml
import os
import glob
from pathlib import Path
import combine_data_for_checklist

CHECKLIST_DICT = combine_data_for_checklist.get_checklist_dict()

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

def list_of_dicts_to_md_table(data, column_titles=None, column_align=None):
    if column_titles is None: column_titles = {key:key.title() for (key,_) in data[0].items()}
    df = pandas.DataFrame.from_dict(data).rename(columns=column_titles)
    return df.to_markdown(index=False, colalign=column_align)

def append_to_file(new_content, file_path):
    file = Path(file_path)
    content = file.read_text() + new_content
    file.write_text(content)

def get_mastg_components_dict(name):
    
        components = []
    
        for file in glob.glob(f"{name}/**/*.md", recursive=True):
            if "index.md" not in file:
                with open(file, 'r') as f:
                    content = f.read()
        
                    frontmatter = next(yaml.load_all(content, Loader=yaml.FullLoader))
                    # is is the basename of the file without the extension
                    id = os.path.splitext(os.path.basename(file))[0]
                    if "-TEST" in id:
                        masvs_id = frontmatter['masvs_v2_id'][0]
                        masvs_category = masvs_id[:masvs_id.rfind('-')]
                        frontmatter['id'] = f"[{id}](/MASTG/{name.split('/')[2]}/{frontmatter['platform']}/{masvs_category}/{id})"

                    else:
                        frontmatter['id'] = f"[{id}](/MASTG/{name.split('/')[2]}/{frontmatter['platform']}/{id})"
                    components.append(frontmatter)
        return components

def reorder_dict_keys(original_dict, key_order):
    return {key: original_dict.get(key, "N/A") for key in key_order}

# tests/index.md

column_titles = {'id': 'ID', 'title': 'Name', 'masvs_v2_id': "MASVS v2 ID", 'masvs_v1_id': "MASVS v1 IDs", 'last_updated': 'Last Updated'} #'id': 'ID',  ... , 'refs': 'Refs', 'techniques': 'Techniques'

tests = get_mastg_components_dict("docs/MASTG/tests")
test_types = ["android", "ios"]
for test_type in test_types:
    append_to_file(f"## {test_type.title()} tests\n\n<br>\n\n", "docs/MASTG/tests/index.md")
    tests_of_type = [reorder_dict_keys(test, column_titles.keys()) for test in tests if test['platform'] == test_type]
    for test in tests_of_type:
        test['masvs_v2_id'] = test['masvs_v2_id'][0]
        if test.get(masvs_v1_id):
            test['masvs_v1_id'] = "\n".join([f"{v1_id}" for v1_id in test['masvs_v1_id']])
    

    for group_id, checklist in CHECKLIST_DICT.items():
        append_to_file(f"### {group_id}\n\n<br>\n\n", "docs/MASTG/tests/index.md")

        tests_by_category = [test for test in tests_of_type if test['masvs_v2_id'].startswith(group_id)]

        # sort the dicts within tests_by_category by MASVS ID
        tests_by_category.sort(key=lambda x: x['masvs_v2_id'])

        append_to_file(list_of_dicts_to_md_table(tests_by_category, column_titles) + "\n\n<br>\n\n", "docs/MASTG/tests/index.md")

# tools/index.md

column_titles = {'id': 'ID', 'title': 'Name', 'platform': "Platform"} # TODO , 'refs': 'Refs', 'techniques': 'Techniques'

tools = get_mastg_components_dict("docs/MASTG/tools")
tool_types = ["generic", "android", "ios", "network"]
for tool_type in tool_types:
    append_to_file(f"## {tool_type.title()} Tools\n\n<br>\n\n", "docs/MASTG/tools/index.md")
    tools_of_type = [reorder_dict_keys(tool, column_titles.keys()) for tool in tools if tool['platform'] == tool_type]
    append_to_file(list_of_dicts_to_md_table(tools_of_type, column_titles) + "\n\n<br>\n\n", "docs/MASTG/tools/index.md")

# techniques/index.md

column_titles = {'id': 'ID', 'title': 'Name', 'platform': "Platform"} # TODO , 'tools': 'Tools'

techniques = get_mastg_components_dict("docs/MASTG/techniques")
technique_types = ["generic", "android", "ios"]

for technique_type in technique_types:
    append_to_file(f"## {technique_type.title()} Techniques\n\n<br>\n\n", "docs/MASTG/techniques/index.md")
    techniques_of_type = [reorder_dict_keys(technique, column_titles.keys()) for technique in techniques if technique['platform'] == technique_type]
    append_to_file(list_of_dicts_to_md_table(techniques_of_type, column_titles) + "\n\n<br>\n\n", "docs/MASTG/techniques/index.md")

# apps/index.md

column_titles = {'id': 'ID', 'title': 'Name', 'platform': "Platform"} # TODO , 'techniques': 'Used in'

apps = get_mastg_components_dict("docs/MASTG/apps")
app_types = ["android", "ios"]

for app_type in app_types:
    append_to_file(f"## {app_type.title()} Apps\n\n<br>\n\n", "docs/MASTG/apps/index.md")
    apps_of_type = [reorder_dict_keys(app, column_titles.keys()) for app in apps if app['platform'] == app_type]
    append_to_file(list_of_dicts_to_md_table(apps_of_type, column_titles) + "\n\n<br>\n\n", "docs/MASTG/apps/index.md")

# talks.md

data = yaml.safe_load(open("docs/assets/data/talks.yaml"))

for element in data:
    if element['video'].startswith("http"):
        element['video'] = f"[:octicons-play-24: Video]({element['video']})"
    if element['slides'].startswith("http"):
        element['slides'] = f"[:material-file-presentation-box: Slides]({element['slides']})"

append_to_file(list_of_dicts_to_md_table(data) + "\n\n<br>\n", "docs/talks.md")

# checklists.md

CHECKLISTS_DIR = "docs/checklists"



column_titles = {'MASVS-ID': 'MASVS-ID', 'Platform': "Platform", 'Control / MASTG Test': 'Control / MASTG Test', 'L1': 'L1', 'L2': 'L2', 'R': 'R'}
column_align = ("left", "center", "left", "center", "center", "center")

warning = '''\
!!! warning "Temporary Checklist"
    This checklist contains the **old MASVS v1 verification levels (L1, L2 and R)** which we are currently reworking into "security testing profiles". The levels were assigned according to the MASVS v1 ID that the test was previously covering and might differ in the upcoming version of the MASTG and MAS Checklist.

    For the upcoming of the MASTG version we will progressively split the MASTG tests into smaller tests, the so-called "atomic tests" and assign the new MAS profiles accordingly.
'''

os.makedirs(CHECKLISTS_DIR, exist_ok=True)

for group_id, checklist in CHECKLIST_DICT.items():
    set_icons_for_web(checklist)
    content = list_of_dicts_to_md_table(checklist, column_titles, column_align) + "\n\n<br><br>"
    
    # add temporary warning
    content = warning + content

    with open(f"{CHECKLISTS_DIR}/{group_id}.md", 'w') as f:
        f.write(f"---\nhide:\n  - toc\n---\n\n{content}\n")
