import os
import re
import yaml

def append_tests_as_subsections():
    testing_chapters = [filename for filename in os.listdir('Document/') if re.match(r'^(0x05|0x06).*-Testing-.*\.md$', filename)]
    for testing_chapter in testing_chapters:
        path = os.path.join('Document', testing_chapter)
        with open(path, 'r') as f:
            testing_chapter_content = f.read()
            chapter_metadata = next(yaml.load_all(testing_chapter_content, Loader=yaml.FullLoader))

        chapter_tests_content = ""

        platform = chapter_metadata['platform']
        masvs_category = chapter_metadata['masvs_category']

        path = os.path.join('tests', platform, masvs_category)
        for test_file in os.listdir(path):
        
            with open(os.path.join(path, test_file), 'r') as f:
                test_content = f.read()
                # Extract yaml frontmatter
                yaml_front = next(yaml.load_all(test_content, Loader=yaml.FullLoader))
                # Extract title and masvs_id
                title = yaml_front['title']
                masvs_v1_id = yaml_front['masvs_v1_id']
                masvs_v2_id = yaml_front['masvs_v2_id']
                # Add title header to content
                chapter_tests_content += f"\n\n## {title}"
                # Add MASVS header to content
                chapter_tests_content += f"\n\n> **MASVS V1:** {', '.join(masvs_v1_id)}\n>\n> **MASVS V2:** {'N/A' if not masvs_v2_id else ', '.join(masvs_v2_id)}\n"
                # Remove yaml frontmatter from test content
                test_content = re.sub(r'---\n(.|\n)*?\n---\n', '', test_content)
                # Add one nesting level to all headers
                test_content = re.sub(r'^#', '##', test_content, flags=re.MULTILINE)

                chapter_tests_content += '\n' + test_content.strip()

        # Write the updated content to the file
        with open(os.path.join('Document', testing_chapter), 'a') as f:
            content = chapter_tests_content + '\n'
            f.write(content)

append_tests_as_subsections()

