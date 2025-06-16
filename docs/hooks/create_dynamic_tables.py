import pandas
import yaml
import os
import glob
import mkdocs
from pathlib import Path
import yaml
import re
import logging

import requests
log = logging.getLogger('mkdocs')
MASVS = None

def get_level_icon(level, value):
    if level == "L1" and value == True:
        return '<span class="mas-dot-blue"></span><span style="display: none;">profile:L1</span>'
    elif level == "L2" and value == True:
        return '<span class="mas-dot-green"></span><span style="display: none;">profile:L2</span>'
    elif level == "R" and value == True:
        return '<span class="mas-dot-orange"></span><span style="display: none;">profile:R</span>'
    elif level == "P" and value == True:
        return '<span class="mas-dot-purple"></span><span style="display: none;">profile:P</span>'

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

def get_all_weaknessess():

    weaknesses = []

    for file in glob.glob("docs/MASWE/**/MASWE-*.md", recursive=True):
        with open(file, 'r') as f:
            content = f.read()

            frontmatter = next(yaml.load_all(content, Loader=yaml.FullLoader))
            frontmatter['path'] = f"/MASWE/{os.path.splitext(os.path.relpath(file, 'docs/MASWE'))[0]}"
            weaknesses_id = frontmatter['id']
            frontmatter['id'] = weaknesses_id
            frontmatter['title'] = f"@{frontmatter['id']}"
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
            elif status == 'placeholder':
                frontmatter['status'] = f'<a href="https://github.com/OWASP/owasp-mastg/issues?q=is%3Aopen+in%3Atitle+%22{weaknesses_id}%22" target="_blank"><span class="md-tag md-tag-icon md-tag--placeholder" style="min-width: 4em">placeholder</span></a><span style="display: none;">status:placeholder</span>'
            elif status == 'deprecated':
                frontmatter['status'] = '<span class="md-tag md-tag-icon md-tag--deprecated">deprecated</span><span style="display: none;">status:deprecated</span>'
            frontmatter['platform'] = "".join([get_platform_icon(platform) for platform in frontmatter['platform']])
            weaknesses.append(frontmatter)

    return weaknesses

weaknesses = get_all_weaknessess()
MASWE = {weakness['id']: weakness for weakness in weaknesses}

def get_platform(input_file: str) -> str:
    if "/android/" in input_file:
        return "android"
    elif "/ios/" in input_file:
        return "ios"

def get_mastg_tests_dict():

    mastg_tests = {}

    for file in glob.glob("docs/MASTG/tests/**/*.md", recursive=True):
        if "index.md" not in file:
            with open(file, 'r') as f:
                id = ""
                content = f.read()
                platform = get_platform(file)
                try:
                    frontmatter = next(yaml.load_all(content, Loader=yaml.FullLoader))
                    if not frontmatter.get('masvs_v2_id'):
                        frontmatter['masvs_v2_id'] = []
                        if frontmatter['weakness'] in MASWE:
                            frontmatter['masvs_v2_id'].append(MASWE[frontmatter['weakness']]['masvs_v2_id'])
                    masvs_v2_id = frontmatter['masvs_v2_id']
                    frontmatter['path'] = os.path.relpath(file, "docs/MASTG")
                    if masvs_v2_id:
                        id = masvs_v2_id[0]
                        if id not in mastg_tests:
                            mastg_tests[id] = {}
                        if platform not in mastg_tests[id]:
                            mastg_tests[id][platform] = []

                        MASTG_TEST_ID = re.compile(r".*(MASTG-TEST-\d*).md$").match(file).group(1)
                        frontmatter['MASTG-TEST-ID'] = MASTG_TEST_ID
                        mastg_tests[id][platform].append(frontmatter)
                    else:
                        print(f"No MASVS v2 coverage for: {frontmatter['title']} (was {frontmatter['masvs_v1_id']})")
                except StopIteration:
                    continue
    return mastg_tests

def retrieve_masvs(version="latest"):
    global MASVS
    try:
        url = f"https://github.com/OWASP/owasp-masvs/releases/{version}/download/OWASP_MASVS.yaml"
        response = requests.get(url)
        content = response.content
    except Exception as e:
        log.warning("⚠️ Connection failed when retrieving OWASP_MASVS.yaml")
        masvs_yaml_file = Path("OWASP_MASVS.yaml")
        if masvs_yaml_file.exists():
            log.warning("⚠️ Reading OWASP_MASVS.yaml from file")
            content = masvs_yaml_file.read_text()
        else:
            raise Exception("ERROR Failed reading OWASP_MASVS.yaml from file")
    MASVS = yaml.safe_load(content)
    return MASVS

def get_masvs_groups():
    groups = {}
    for group in MASVS['groups']:
        group_id = group['id']
        groups[group_id] = {'id': group_id, 'title': group['title']}
    return groups

def add_control_row(checklist, control):
    checklist_row = {}
    checklist_row['MASVS-ID'] = control['id']
    checklist_row['path'] = f"./MASVS/controls/{os.path.basename(control['id'])}"
    checklist_row['Platform'] = ""
    checklist_row['Control / MASTG Test'] = control['statement']
    checklist_row['MASTG-TEST-ID'] = ""
    checklist_row['L1'] = ""
    checklist_row['L2'] = ""
    checklist_row['R'] = ""
    checklist_row['P'] = ""
    checklist_row['Status'] = ""
    checklist.append(checklist_row)

def add_test_rows(checklist, platform, control):
    if platform in control['tests']:
        for test in control['tests'][platform]:
            levels = test['profiles']
            checklist_row = {}
            checklist_row['MASVS-ID'] = "" # test['masvs_v2_id'][0] if test['masvs_v2_id'] else ""
            # checklist_row['Weakness'] = test.get('weakness', "")
            checklist_row['path'] = f"/MASTG/{os.path.splitext(test['path'])[0]}"
            checklist_row['Platform'] = test['platform']
            checklist_row['Control / MASTG Test'] = test['title']
            checklist_row['MASTG-TEST-ID'] = test["MASTG-TEST-ID"]
            checklist_row['L1'] = "L1" in levels
            checklist_row['L2'] = "L2" in levels
            checklist_row['R'] = "R" in levels
            checklist_row['P'] = "P" in levels
            if "MASTG-TEST-00" in test['MASTG-TEST-ID']:
                checklist_row['Status'] = test.get('status', 'update-pending')
            elif "MASTG-TEST-02" in test['MASTG-TEST-ID']:
                checklist_row['Status'] = test.get('status', 'new')
            checklist.append(checklist_row)

def get_checklist_dict():
    masvs_v2 = retrieve_masvs()

    mastg_tests = get_mastg_tests_dict()

    checklist_dict = {}

    for group in masvs_v2['groups']:

        checklist_per_group = []

        for control in group['controls']:
            add_control_row(checklist_per_group, control)
            control_id = control['id']
            if control_id in mastg_tests:
                control['tests'] = mastg_tests[control_id]
                add_test_rows(checklist_per_group, "android", control)
                add_test_rows(checklist_per_group, "ios", control)

        checklist_dict[group['id']] = checklist_per_group
    return checklist_dict

CHECKLIST_DICT = {}
def on_pre_build(config):
    global CHECKLIST_DICT
    CHECKLIST_DICT = get_checklist_dict()

def set_icons_for_web(checklist):

    for row in checklist:
        # if it's a control row, make the MASVS-ID and Control bold
        if row['Platform'] == "":
            relPath = os.path.relpath(row['path'], './checklists/') + ".md"
            row['MASVS-ID'] = f"**[{row['MASVS-ID']}]({relPath})**"
            row['Control / MASTG Test'] = f"**{row['Control / MASTG Test']}**"

        # if it's a test row, set the icons for platform and levels
        else:
            row['Platform'] = get_platform_icon(row['Platform'])
            row['Control / MASTG Test'] = f"@{row['MASTG-TEST-ID']}"
            row['L1'] = get_level_icon('L1', row['L1'])
            row['L2'] = get_level_icon('L2', row['L2'])
            row['R'] = get_level_icon('R', row['R'])
            row['P'] = get_level_icon('P', row['P'])

            test_id = row['MASTG-TEST-ID']

            row['MASTG-TEST-ID'] = f'<span style="display:inline-block; border-radius:2.4em; background:#499fffff; color: white; padding:0.2em 0.8em; font-size:75%;">{row["MASTG-TEST-ID"]}</span><span style="display: none;">{row["MASTG-TEST-ID"]}</span>'

            # Process status field for test rows
            status = row.get('Status')
            if status == 'new':
                row['Status'] = '<span class="md-tag md-tag-icon md-tag--new">new</span><span style="display: none;">status:new</span>'
            elif status == 'placeholder':
                row['Status'] = f'<a href="https://github.com/OWASP/owasp-mastg/issues?q=is%3Aopen+in%3Atitle+%22{test_id}%22" target="_blank"><span class="md-tag md-tag-icon md-tag--placeholder" style="min-width: 4em;">placeholder</span></a><span style="display: none;">status:placeholder</span>'
            elif status == 'deprecated':
                row['Status'] = '<span class="md-tag md-tag-icon md-tag--deprecated">deprecated</span><span style="display: none;">status:deprecated</span>'
            elif status == 'update-pending':
                row['Status'] = f'<a href="https://github.com/OWASP/owasp-mastg/issues?q=is%3Aopen+in%3Atitle+%22{test_id}%22" target="_blank"><span class="md-tag md-tag-icon md-tag--update-pending" style="min-width: 4em;">update-pending</span></a><span style="display: none;">status:update-pending</span>'

def list_of_dicts_to_md_table(data, column_titles=None, column_align=None):

    if column_titles is None:
        column_titles = {key:key.title() for (key,_) in data[0].items()}

    df = pandas.DataFrame.from_dict(data).rename(columns=column_titles)
    return df.to_markdown(index=False, colalign=column_align)

def append_to_page(markdown, new_content, tableid=""):

    return markdown + f"\n<div id='{tableid}' markdown='1'>\n"+ new_content + "</div>\n\n<br>\n\n"


def get_mastg_components_dict(name):

        components = []

        for file in glob.glob(f"{name}/**/*.md", recursive=True):
            if "index.md" not in file:
                with open(file, 'r') as f:
                    content = f.read()

                    frontmatter = next(yaml.load_all(content, Loader=yaml.FullLoader))
                    component_id = os.path.splitext(os.path.basename(file))[0]
                    component_path = os.path.splitext(os.path.relpath(file, "docs/"))[0]
                    frontmatter['id'] = component_id
                    frontmatter['title'] = f"@{component_id}"
                    if frontmatter.get('platform') and type(frontmatter['platform']) == list:
                        frontmatter['platform'] = "".join([get_platform_icon(platform) for platform in frontmatter['platform']])
                    else:
                        frontmatter['platform'] = get_platform_icon(frontmatter['platform'])

                    profiles = frontmatter.get('profiles', [])
                    frontmatter['L1'] = get_level_icon('L1', "L1" in profiles)
                    frontmatter['L2'] = get_level_icon('L2', "L2" in profiles)
                    frontmatter['R'] = get_level_icon('R', "R" in profiles)
                    frontmatter['P'] = get_level_icon('P', "P" in profiles)

                    if "MASTG-TEST-00" in component_id:
                        frontmatter['status'] = frontmatter.get('status', 'update-pending')
                        if frontmatter['status'] == 'update-pending':
                            # add github link to the issue tracker
                            frontmatter['status'] = f'<a href="https://github.com/OWASP/owasp-mastg/issues?q=is%3Aopen+in%3Atitle+%22{component_id}%22" target="_blank"><span class="md-tag md-tag-icon md-tag--update-pending" style="min-width: 4em">update-pending</span></a><span style="display: none;">status:update-pending</span>'
                        elif frontmatter['status'] == 'deprecated':
                            frontmatter['status'] = '<span class="md-tag md-tag-icon md-tag--deprecated">deprecated</span><span style="display: none;">status:deprecated</span>'
                    elif "MASTG-TEST-02" in component_id:
                        frontmatter['status'] = frontmatter.get('status', 'new')
                        if frontmatter['status'] == 'new':
                            frontmatter['status'] = '<span class="md-tag md-tag-icon md-tag--new">new</span><span style="display: none;">status:new</span>'
                        elif frontmatter['status'] == 'placeholder':
                            frontmatter['status'] = f'<a href="https://github.com/OWASP/owasp-mastg/issues?q=is%3Aopen+in%3Atitle+%22{component_id}%22" target="_blank"><span class="md-tag md-tag-icon md-tag--placeholder" style="min-width: 4em">placeholder</span></a><span style="display: none;">status:placeholder</span>'
                        elif frontmatter['status'] == 'deprecated':
                            frontmatter['status'] = '<span class="md-tag md-tag-icon md-tag--deprecated">deprecated</span><span style="display: none;">status:deprecated</span>'

                    components.append(frontmatter)
        return components



def get_all_demos_beta():

    demos = []

    for file in glob.glob("docs/MASTG/demos/**/MASTG-DEMO-*.md", recursive=True):
        with open(file, 'r') as f:
            content = f.read()

            frontmatter = next(yaml.load_all(content, Loader=yaml.FullLoader))

            frontmatter['path'] = f"/MASTG/demos/{os.path.splitext(os.path.relpath(file, 'docs/MASTG/demos'))[0]}"
            demo_id = frontmatter['id']
            frontmatter['id'] = demo_id
            frontmatter['title'] = f"@{demo_id}"
            frontmatter['platform'] = get_platform_icon(frontmatter['platform'])
            frontmatter['status'] = frontmatter.get('status', 'new')
            status = frontmatter['status']
            if status == 'new':
                frontmatter['status'] = '<span class="md-tag md-tag-icon md-tag--new">new</span><span style="display: none;">status:new</span>'
            elif status == 'placeholder':
                frontmatter['status'] = f'<a href="https://github.com/OWASP/owasp-mastg/issues?q=is%3Aopen+in%3Atitle+%22{demo_id}%22" target="_blank"><span class="md-tag md-tag-icon md-tag--placeholder" style="min-width: 4em">placeholder</span></a><span style="display: none;">status:placeholder</span>'
            elif status == 'deprecated':
                frontmatter['status'] = '<span class="md-tag md-tag-icon md-tag--deprecated">deprecated</span><span style="display: none;">status:deprecated</span>'

            demos.append(frontmatter)
    return demos

def get_all_mitigations_beta():

        mitigations = []

        for file in glob.glob("docs/MASTG/best-practices/**/MASTG-BEST-*.md", recursive=True):
            with open(file, 'r') as f:
                content = f.read()

                frontmatter = next(yaml.load_all(content, Loader=yaml.FullLoader))

                frontmatter['path'] = f"/MASTG/best-practices/{os.path.splitext(os.path.relpath(file, 'docs/MASTG/best-practices'))[0]}"
                mitigation_id = frontmatter['id']
                frontmatter['id'] = mitigation_id
                frontmatter['title'] = f"@{mitigation_id}"
                frontmatter['platform'] = get_platform_icon(frontmatter['platform'])

                mitigations.append(frontmatter)
        return mitigations

def reorder_dict_keys(original_dict, key_order):
    return {key: original_dict.get(key, "N/A") for key in key_order}

# Higher priority, so that tables are parsed by the other hooks too
@mkdocs.plugins.event_priority(-40)
def on_page_markdown(markdown, page, config, **kwargs):

    path = page.file.src_uri

    if path.endswith('/tests/index.md'):

        # tests/index.md

        column_titles = {'id': 'ID', 'title': 'Title', 'platform': "Platform", 'L1': 'L1', 'L2': 'L2', 'R': 'R', 'P': 'P', 'status': 'Status'} # 'masvs_v2_id': "MASVS v2 ID", 'masvs_v1_id': "MASVS v1 IDs",
        tests = get_mastg_components_dict("docs/MASTG/tests")
        tests_of_type = [reorder_dict_keys(test, column_titles.keys()) for test in tests]
        for test in tests_of_type:
            if test.get("masvs_v2_id"):
                test['masvs_v2_id'] = test['masvs_v2_id'][0]
            if test.get("masvs_v1_id"):
                test['masvs_v1_id'] = "<br>".join([f"{v1_id}" for v1_id in test['masvs_v1_id']])
        return append_to_page(markdown, list_of_dicts_to_md_table(tests_of_type, column_titles), "table_tests")

    elif path.endswith("demos/index.md"):
        # demos/index.md

        column_titles = {'id': 'ID', 'title': 'Title', 'platform': "Platform", 'test': "Test", 'status': "Status"} # TODO , 'tools': "Tools"

        demos_beta = config["demos_beta"]
        demos_beta_columns_reordered = [reorder_dict_keys(demo, column_titles.keys()) for demo in demos_beta]

        return append_to_page(markdown, list_of_dicts_to_md_table(demos_beta_columns_reordered, column_titles))

    elif path.endswith("best-practices/index.md"):
        # mitigations/index.md

        column_titles = {'id': 'ID', 'title': 'Title', 'platform': "Platform"}

        mitigations_beta = config["mitigations_beta"]
        mitigations_beta_columns_reordered = [reorder_dict_keys(mitigation, column_titles.keys()) for mitigation in mitigations_beta]

        return append_to_page(markdown, list_of_dicts_to_md_table(mitigations_beta_columns_reordered, column_titles))

    elif path.endswith("tools/index.md"):

        # tools/index.md

        column_titles = {'id': 'ID', 'title': 'Name', 'platform': "Platform"} # TODO , 'refs': 'Refs', 'techniques': 'Techniques'

        tools = get_mastg_components_dict("docs/MASTG/tools")
        tools_of_type = [reorder_dict_keys(tool, column_titles.keys()) for tool in tools]
        return append_to_page(markdown, "\n" + list_of_dicts_to_md_table(tools_of_type, column_titles))

    elif path.endswith("techniques/index.md"):
        # techniques/index.md

        column_titles = {'id': 'ID', 'title': 'Name', 'platform': "Platform"} # TODO , 'tools': 'Tools'

        techniques = get_mastg_components_dict("docs/MASTG/techniques")
        techniques_of_type = [reorder_dict_keys(technique, column_titles.keys()) for technique in techniques]
        return append_to_page(markdown, list_of_dicts_to_md_table(techniques_of_type, column_titles) )

    elif path.endswith("apps/index.md"):
        # apps/index.md

        column_titles = {'id': 'ID', 'title': 'Name', 'platform': "Platform"} # TODO , 'techniques': 'Used in'

        apps = get_mastg_components_dict("docs/MASTG/apps")
        apps_of_type = [reorder_dict_keys(app, column_titles.keys()) for app in apps]
        return append_to_page(markdown, list_of_dicts_to_md_table(apps_of_type, column_titles) )

    elif path.endswith("MASWE/index.md"):
        # weaknesses/index.md

        column_titles = {'id': 'ID', 'title': 'Title', 'platform': "Platform", 'masvs_v2_id': "MASVS v2 ID", 'L1': 'L1', 'L2': 'L2', 'R': 'R', 'P': 'P', 'status': 'Status'}

        weaknesses = get_all_weaknessess()
        weaknesses_columns_reordered = [reorder_dict_keys(weakness, column_titles.keys()) for weakness in weaknesses]

        return append_to_page(markdown, list_of_dicts_to_md_table(weaknesses_columns_reordered, column_titles) )

    elif path.endswith("talks.md"):
        # talks.md

        data = yaml.safe_load(open("docs/assets/data/talks.yaml"))

        for element in data:
            if element['video'].startswith("http"):
                element['video'] = f"[:octicons-play-24: Video]({element['video']})"
            if element['slides'].startswith("http"):
                element['slides'] = f"[:material-file-presentation-box: Slides]({element['slides']})"

        return append_to_page(markdown, list_of_dicts_to_md_table(data))

    elif path and re.compile(r"^checklists/MASVS-\w*\.md$").match(path):
        # checklists.md

        column_titles = {'MASVS-ID': 'MASVS-ID', 'MASTG-TEST-ID': 'MASTG-TEST-ID', 'Control / MASTG Test': 'Control / MASTG Test',  'Platform': "Platform", 'L1': 'L1', 'L2': 'L2', 'R': 'R', 'P': 'P', 'Status': 'Status'}
        column_align = ("left", "center", "left", "center", "left", "center", "center", "center", "center")

        ID = re.compile(r"^checklists/(MASVS-\w*)\.md$").match(path).group(1)
        checklist = CHECKLIST_DICT[ID]

        set_icons_for_web(checklist)

        cleaned_checklist = []
        for check in checklist:
            cleaned_check = dict(check)

            del cleaned_check['path']
            cleaned_checklist.append(cleaned_check)

        cleaned_checklist = [reorder_dict_keys(check, column_titles.keys()) for check in cleaned_checklist]

        content = list_of_dicts_to_md_table(cleaned_checklist, column_titles, column_align) + "\n\n<br><br>"

        return append_to_page(markdown, content)


    return markdown


def on_config(config):
    config["mitigations_beta"] = get_all_mitigations_beta()
    config["demos_beta"] = get_all_demos_beta()