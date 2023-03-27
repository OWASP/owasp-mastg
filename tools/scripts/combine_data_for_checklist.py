import yaml
import get_tests_dict

def add_control_row(checklist, control):
    checklist_row = {}
    checklist_row['MASVS-ID'] = control['id']
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
            checklist_row['Platform'] = test['platform']
            checklist_row['Control / MASTG Test'] = test['title']
            checklist_row['L1'] = "L1" in levels
            checklist_row['L2'] = "L2" in levels
            checklist_row['R'] = "R" in levels
            checklist.append(checklist_row)

def get_checklist_dict():
    masvs_v2 = yaml.load(open('Document/masvs_v2.0.0.yaml', 'r'), Loader=yaml.FullLoader)

    mastg_tests = get_tests_dict.get_mastg_tests_dict()

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
