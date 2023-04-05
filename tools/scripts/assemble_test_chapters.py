import os
import re
import yaml
import pandas
import argparse

import get_tests_dict

def dict_to_md(data, column_titles=None):
    if column_titles is None: column_titles = {key:key.title() for (key,_) in data[0].items()}
    df = pandas.DataFrame.from_dict(data).rename(columns=column_titles)
    return df.to_markdown(index=False)

def is_test_deprecated(test):
    return test['masvs_v2_id'] == []

def inject_tests_table():
    
    mastg_tests = get_tests_dict.get_mastg_tests_dict()

    for filename in os.listdir('Document/'):
        if re.match(r"0x0[5-6][d-j].*.md", filename):
            base_name = os.path.splitext(filename)[0]

            # Read the content of the file
            with open(os.path.join('Document', filename), 'r') as f:
                content = f.read()
            
            list_of_tests = []
            # for masvs_id in mastg_tests and platform in mastg_tests[masvs_id] append test to list_of_tests
            for masvs_id in mastg_tests:
                for platform in mastg_tests[masvs_id]:
                    for test in mastg_tests[masvs_id][platform]:
                        if base_name in test['path'] and is_test_deprecated(test) == False:
                            md_link = f"[{test['title']}](/MASTG/tests/{os.path.splitext(os.path.basename(test['path']))[0]})"
                            t = {}
                            t['title'] = md_link
                            t['masvs_v1_id'] = ", ".join(test['masvs_v1_id'])
                            t['masvs_v2_id'] = ", ".join(test['masvs_v2_id'])
                            t['masvs_v1_levels'] = ", ".join(test['masvs_v1_levels'])
                            
                            list_of_tests.append(t)
            content += '\n## Tests\n'

            if list_of_tests:
                column_titles = {'title': 'Title', 'masvs_v1_id': 'MASVS V1', 'masvs_v2_id': 'MASVS V2', 'masvs_v1_levels': 'MASVS V1 Levels'}
                tests_md_table = dict_to_md(list_of_tests, column_titles)                
                content += '\n' + tests_md_table
            else:
                content += '\nNo tests available for this chapter.'

            # Write the updated content to the file
            with open(os.path.join('Document', filename), 'w') as f:
                content += '\n'
                f.write(content)

def append_tests_as_subsections():
    for filename in os.listdir('Document/'):
        if filename.endswith(".md") and "-Testing-" in filename:
            # Extract the base name of the file
            base_name = os.path.splitext(filename)[0]

            # TODO remove deprecated logic
            # TODO remove dependency on base_name 

            # Read the content of the file
            with open(os.path.join('Document', filename), 'r') as f:
                content = f.read()
            if os.path.exists(os.path.join('tests', base_name)):
                # Find all the matching test files and concatenate their content
                for test_file in os.listdir(os.path.join('tests', base_name)):
                    if test_file.endswith(".md"):
                        with open(os.path.join('tests', base_name, test_file), 'r') as f:
                            test_content = f.read()
                            # Extract yaml frontmatter
                            match = re.match(r'---\n(.|\n)*?\n---\n', test_content)
                            if match:
                                yaml_front = next(yaml.load_all(test_content, Loader=yaml.FullLoader))
                                # Extract title and masvs_id
                                title = yaml_front['title']
                                masvs_v1_id = yaml_front['masvs_v1_id']
                                masvs_v2_id = yaml_front['masvs_v2_id']
                                deprecated = "(DEPRECATED) " if is_test_deprecated(yaml_front) else ""
                                # Add title header to content
                                content += f"\n\n## {deprecated}{title}"
                                # Add MASVS header to content
                                content += f"\n\n> **MASVS V1:** {', '.join(masvs_v1_id)}\n>\n> **MASVS V2:** {'N/A' if not masvs_v2_id else ', '.join(masvs_v2_id)}\n"
                                # Remove yaml frontmatter from test content
                                test_content = re.sub(r'---\n(.|\n)*?\n---\n', '', test_content)
                                # Add one nesting level to all headers
                                test_content = re.sub(r'^#', '##', test_content, flags=re.MULTILINE)

                                content += '\n' + test_content.strip()

                # Write the updated content to the file
                with open(os.path.join('Document', filename), 'w') as f:
                    content += '\n'
                    f.write(content)


# get input arguments
parser = argparse.ArgumentParser()
parser.add_argument("-w", "--website", help="Generate for website", action='store_true', required=False, default=False)
args = parser.parse_args()

for_website = args.website

if for_website:
    inject_tests_table()
else:
    append_tests_as_subsections()

