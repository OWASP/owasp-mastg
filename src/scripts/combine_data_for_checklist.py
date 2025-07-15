import yaml
import os
import glob
import re

import requests

MASVS = None

def retrieve_masvs(version="latest"):
    global MASVS
    url = f"https://github.com/OWASP/masvs/releases/{version}/download/OWASP_MASVS.yaml"
    response = requests.get(url)
    content = response.content
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
    checklist_row['path'] = f"/MASVS/controls/{os.path.basename(control['id'])}"
    checklist_row['Platform'] = ""
    checklist_row['Control / MASTG Test'] = control['statement']
    checklist_row['L1'] = ""
    checklist_row['L2'] = ""
    checklist_row['R'] = ""
    checklist.append(checklist_row)

def add_test_rows(checklist, platform, control):
    if platform in control['tests']:
        for test in control['tests'][platform]:
            levels = test['masvs_v1_levels']
            checklist_row = {}
            checklist_row['MASVS-ID'] = ""
            checklist_row['path'] = f"/MASTG/{os.path.splitext(test['path'])[0]}"
            checklist_row['Platform'] = test['platform']
            checklist_row['Control / MASTG Test'] = test['title']
            checklist_row['L1'] = "L1" in levels
            checklist_row['L2'] = "L2" in levels
            checklist_row['R'] = "R" in levels
            checklist.append(checklist_row)


def get_platform(input_file: str) -> str:
    if "/android/" in input_file:
        return "android"
    elif "/ios/" in input_file:
        return "ios"

def get_mastg_tests_dict():

    mastg_tests = {}

    for file in glob.glob("tests/**/*.md", recursive=True):
        if file == "tests/index.md":
            continue
        with open(file, 'r') as f:
            id = ""
            content = f.read()
            platform = get_platform(file)
            try:
                
                frontmatter = next(yaml.load_all(content, Loader=yaml.FullLoader))
                masvs_v2_id = frontmatter.get('masvs_v2_id')
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
