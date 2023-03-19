import os
import re
import yaml

def concatenate_tests():
    for filename in os.listdir('Document/'):
        if filename.endswith(".md") and "-Testing-" in filename:
            # Extract the base name of the file
            base_name = os.path.splitext(filename)[0]

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
                                # Add title header to content
                                content += f"\n\n## {title}"
                                # Add MASVS header to content
                                content += f"\n\n> MASVS V1: {', '.join(masvs_v1_id)}\n> MASVS V2: {'N/A' if not masvs_v2_id else ', '.join(masvs_v2_id)}"
                                # Remove yaml frontmatter from test content
                                test_content = re.sub(r'---\n(.|\n)*?\n---\n', '', test_content)
                                # use regex to add one more # to all markdown headers in test_content
                                test_content = re.sub(r'^#', '##', test_content, flags=re.MULTILINE)

                                content += '\n\n' + test_content.strip()

                # Write the updated content to the file
                with open(os.path.join('Document', filename), 'w') as f:
                    f.write(content)


concatenate_tests()