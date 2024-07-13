import pandas
import yaml
import os
import glob
from pathlib import Path
import combine_data_for_checklist

CHECKLIST_DICT = combine_data_for_checklist.get_checklist_dict()

def get_platform_icon(platform):
    if platform == "android":
        return '<span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>'
    elif platform == "ios":
        return '<span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>'
    elif platform == "generic":
        return '<span style="font-size: x-large; color: darkgrey;" title="Generic"> :material-asterisk: </span><span style="display: none;">platform:generic</span>'
    elif platform == "network":
        return '<span style="font-size: x-large; color: #9383e2;" title="Network"> :material-web: </span><span style="display: none;">platform:network</span>'
    else:
        return '<span style="font-size: x-large; color: darkgrey;" title="Unknown"> :material-progress-question: </span><span style="display: none;">platform:unknown</span>'

def get_level_icon(level, value):
    if level == "L1" and value == True:
        return '<span class="mas-dot-blue"></span><span style="display: none;">profile:L1</span>'
    elif level == "L2" and value == True:
        return '<span class="mas-dot-green"></span><span style="display: none;">profile:L2</span>'
    elif level == "R" and value == True:
        return '<span class="mas-dot-orange"></span><span style="display: none;">profile:R</span>'
    elif level == "P" and value == True:
        return '<span class="mas-dot-purple"></span><span style="display: none;">profile:P</span>'

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
    if not file.exists():
        file.touch()
    content = file.read_text() + new_content
    file.write_text(content)

def get_mastg_components_dict(name):
    
        components = []
    
        for file in glob.glob(f"{name}/**/*.md", recursive=True):
            if "index.md" not in file:
                with open(file, 'r') as f:
                    content = f.read()
        
                    frontmatter = next(yaml.load_all(content, Loader=yaml.FullLoader))
                    component_id = os.path.splitext(os.path.basename(file))[0]
                    component_path = os.path.splitext(os.path.relpath(file, "docs/"))[0]
                    frontmatter['id'] = f"[{component_id}](/{component_path})"
                    if frontmatter.get('platform') and type(frontmatter['platform']) == list:
                        frontmatter['platform'] = "".join([get_platform_icon(platform) for platform in frontmatter['platform']])
                    else:
                        frontmatter['platform'] = get_platform_icon(frontmatter['platform'])
                    components.append(frontmatter)
        return components

def get_all_weaknessess():

    weaknesses = []

    for file in glob.glob("docs/MASWE/**/MASWE-*.md", recursive=True):
        with open(file, 'r') as f:
            content = f.read()
    
            frontmatter = next(yaml.load_all(content, Loader=yaml.FullLoader))

            frontmatter['path'] = f"/MASWE/{os.path.splitext(os.path.relpath(file, 'docs/MASWE'))[0]}"
            weaknesses_id = frontmatter['id']            
            frontmatter['id'] = f"[{weaknesses_id}]({frontmatter['path']})"
            frontmatter['masvs_v2_id'] = frontmatter['mappings']['masvs-v2'][0]
            frontmatter['masvs_category'] = frontmatter['masvs_v2_id'][:frontmatter['masvs_v2_id'].rfind('-')]
            frontmatter['L1'] = get_level_icon('L1', "L1" in frontmatter['profiles'])
            frontmatter['L2'] = get_level_icon('L2', "L2" in frontmatter['profiles'])
            frontmatter['R'] = get_level_icon('R', "R" in frontmatter['profiles'])
            frontmatter['P'] = get_level_icon('P', "P" in frontmatter['profiles'])
            frontmatter['status'] = frontmatter.get('status', 'new')
            status = frontmatter['status']
            if status == 'new':
                frontmatter['status'] = '<span class="md-tag md-tag-icon md-tag--new">new</span><span style="display: none;">status:new</span>'
            elif status == 'draft':
                frontmatter['status'] = f'<a href="https://github.com/OWASP/owasp-mastg/issues?q=is%3Aissue+is%3Aopen+{weaknesses_id}" target="_blank"><span class="md-tag md-tag-icon md-tag--draft" style="min-width: 4em">draft</span></a><span style="display: none;">status:draft</span>'
            frontmatter['platform'] = "".join([get_platform_icon(platform) for platform in frontmatter['platform']])
            weaknesses.append(frontmatter)

    return weaknesses

def get_all_tests_beta():

    tests = []

    for file in glob.glob("docs/MASTG/tests-beta/**/MASTG-TEST-*.md", recursive=True):
        with open(file, 'r') as f:
            content = f.read()
    
            frontmatter = next(yaml.load_all(content, Loader=yaml.FullLoader))

            frontmatter['path'] = f"/MASTG/tests-beta/{os.path.splitext(os.path.relpath(file, 'docs/MASTG/tests-beta'))[0]}"
            test_id = frontmatter['id']            
            frontmatter['id'] = f"[{test_id}]({frontmatter['path']})"
            frontmatter['platform'] = get_platform_icon(frontmatter['platform'])
            
            tests.append(frontmatter)
    return tests

def get_all_demos_beta():

    demos = []

    for file in glob.glob("docs/MASTG/demos/**/MASTG-DEMO-*.md", recursive=True):
        with open(file, 'r') as f:
            content = f.read()
    
            frontmatter = next(yaml.load_all(content, Loader=yaml.FullLoader))

            frontmatter['path'] = f"/MASTG/demos/{os.path.splitext(os.path.relpath(file, 'docs/MASTG/demos'))[0]}"
            test_id = frontmatter['id']            
            frontmatter['id'] = f"[{test_id}]({frontmatter['path']})"
            frontmatter['platform'] = get_platform_icon(frontmatter['platform'])
            
            demos.append(frontmatter)
    return demos

def reorder_dict_keys(original_dict, key_order):
    return {key: original_dict.get(key, "N/A") for key in key_order}

# tests/index.md

column_titles = {'id': 'ID', 'title': 'Title', 'platform': "Platform", 'masvs_v2_id': "MASVS v2 ID", 'masvs_v1_id': "MASVS v1 IDs", 'last_updated': 'Last Updated'} #'id': 'ID',  ... , 'refs': 'Refs', 'techniques': 'Techniques'
tests = get_mastg_components_dict("docs/MASTG/tests")
tests_of_type = [reorder_dict_keys(test, column_titles.keys()) for test in tests]
for test in tests_of_type:
    if test.get("masvs_v2_id"):
        test['masvs_v2_id'] = test['masvs_v2_id'][0]
    if test.get("masvs_v1_id"):
        test['masvs_v1_id'] = "<br>".join([f"{v1_id}" for v1_id in test['masvs_v1_id']])
append_to_file(list_of_dicts_to_md_table(tests_of_type, column_titles) + "\n\n<br>\n\n", "docs/MASTG/tests/index.md")

# tests-beta/index.md

column_titles = {'id': 'ID', 'title': 'Title', 'platform': "Platform", 'weakness': "Weakness", 'type': "Type"}

tests_beta = get_all_tests_beta()
tests_beta_columns_reordered = [reorder_dict_keys(test, column_titles.keys()) for test in tests_beta]

append_to_file(list_of_dicts_to_md_table(tests_beta_columns_reordered, column_titles) + "\n\n<br>\n\n", "docs/MASTG/tests-beta/index.md")

# demos-beta/index.md

column_titles = {'id': 'ID', 'title': 'Title', 'platform': "Platform", 'test': "Test", 'tools': "Tools"}

demos_beta = get_all_demos_beta()
demos_beta_columns_reordered = [reorder_dict_keys(demo, column_titles.keys()) for demo in demos_beta]

append_to_file(list_of_dicts_to_md_table(demos_beta_columns_reordered, column_titles) + "\n\n<br>\n\n", "docs/MASTG/demos/index.md")

# tools/index.md

column_titles = {'id': 'ID', 'title': 'Name', 'platform': "Platform"} # TODO , 'refs': 'Refs', 'techniques': 'Techniques'

tools = get_mastg_components_dict("docs/MASTG/tools")
tools_of_type = [reorder_dict_keys(tool, column_titles.keys()) for tool in tools]
append_to_file("\n" + list_of_dicts_to_md_table(tools_of_type, column_titles) + "\n\n<br>\n\n", "docs/MASTG/tools/index.md")

# techniques/index.md

column_titles = {'id': 'ID', 'title': 'Name', 'platform': "Platform"} # TODO , 'tools': 'Tools'

techniques = get_mastg_components_dict("docs/MASTG/techniques")
techniques_of_type = [reorder_dict_keys(technique, column_titles.keys()) for technique in techniques]
append_to_file(list_of_dicts_to_md_table(techniques_of_type, column_titles) + "\n\n<br>\n\n", "docs/MASTG/techniques/index.md")

# apps/index.md

column_titles = {'id': 'ID', 'title': 'Name', 'platform': "Platform"} # TODO , 'techniques': 'Used in'

apps = get_mastg_components_dict("docs/MASTG/apps")
apps_of_type = [reorder_dict_keys(app, column_titles.keys()) for app in apps]
append_to_file(list_of_dicts_to_md_table(apps_of_type, column_titles) + "\n\n<br>\n\n", "docs/MASTG/apps/index.md")

# weaknesses/index.md

column_titles = {'id': 'ID', 'title': 'Title', 'platform': "Platform", 'masvs_v2_id': "MASVS v2 ID", 'L1': 'L1', 'L2': 'L2', 'R': 'R', 'P': 'P', 'status': 'Status'}

weaknesses = get_all_weaknessess()
weaknesses_columns_reordered = [reorder_dict_keys(weakness, column_titles.keys()) for weakness in weaknesses]

append_to_file(list_of_dicts_to_md_table(weaknesses_columns_reordered, column_titles) + "\n\n<br>\n\n", "docs/MASWE/index.md")


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

    For the upcoming of the MASTG version we will progressively split the MASTG tests into smaller tests, the so-called "atomic tests" and assign the new [MAS profiles](https://docs.google.com/document/d/1paz7dxKXHzAC9MN7Mnln1JiZwBNyg7Gs364AJ6KudEs/edit?usp=sharing) to their respective MASWE weaknesses.
'''

os.makedirs(CHECKLISTS_DIR, exist_ok=True)

for group_id, checklist in CHECKLIST_DICT.items():
    set_icons_for_web(checklist)
    content = list_of_dicts_to_md_table(checklist, column_titles, column_align) + "\n\n<br><br>"
    
    # add temporary warning
    content = warning + content

    with open(f"{CHECKLISTS_DIR}/{group_id}.md", 'w') as f:
        f.write(f"---\nhide:\n  - toc\n---\n\n{content}\n")
