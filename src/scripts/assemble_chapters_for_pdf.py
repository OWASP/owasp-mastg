import re
import yaml
from pathlib import Path

def append_tests_as_subsections():
    base_document_path = Path('Document')
    base_tests_path = Path('tests')

    testing_chapters = [filename for filename in base_document_path.glob('0x0[56]*-Testing-*.md')]
    for testing_chapter_path in testing_chapters:
        with testing_chapter_path.open('r') as f:
            testing_chapter_content = f.read()
            chapter_metadata = next(yaml.safe_load_all(testing_chapter_content))

        chapter_tests_content = ""

        platform = chapter_metadata['platform']
        masvs_category = chapter_metadata['masvs_category']

        tests_path = base_tests_path / platform / masvs_category
        for test_file in tests_path.glob('*'):
            with test_file.open('r') as f:
                test_content = f.read()
                # Extract yaml frontmatter
                yaml_front = next(yaml.safe_load_all(test_content))
                # Extract title and masvs_id
                title = yaml_front['title']
                platform = yaml_front['platform']
                masvs_v1_id = yaml_front['masvs_v1_id']
                masvs_v2_id = yaml_front['masvs_v2_id']
                # Add title header to content
                chapter_tests_content += f"\n\n## {title}\n"
                chapter_tests_content += f"\n> **Platform:** {platform}\n>\n"
                # Add MASVS header to content
                chapter_tests_content += f"> **MASVS V1:** {', '.join(masvs_v1_id)}\n>\n> **MASVS V2:** {'N/A' if not masvs_v2_id else ', '.join(masvs_v2_id)}\n"
                # Remove yaml frontmatter from test content
                test_content = re.sub(r'---\n(.|\n)*?\n---\n', '', test_content)
                # Add one nesting level to all headers
                test_content = re.sub(r'^#', '##', test_content, flags=re.MULTILINE)

                chapter_tests_content += '\n' + test_content.strip()

        # Write the updated content to the file
        with testing_chapter_path.open('a') as f:
            content = chapter_tests_content + '\n'
            f.write(content)

def append_tools_as_subsections():
    base_document_path = Path('Document')
    base_tools_path = Path('tools')
    tools_chapter_path = base_document_path / '0x08a-Testing-Tools.md'
    
    for platform in ['android', 'ios', 'network', 'generic']:
        chapter_tools_content = ""
        tools_path = base_tools_path / platform
        for tool_file in tools_path.glob('*'):
            with tool_file.open('r') as f:
                tool_content = f.read()
                # Extract yaml frontmatter
                yaml_front = next(yaml.safe_load_all(tool_content))
                # Extract title and source
                title = yaml_front['title']
                platform = yaml_front['platform']
                source = yaml_front.get('source')
                # Add title header to content
                chapter_tools_content += f"\n\n## {title}\n"
                chapter_tools_content += f"\n> **Platform:** {platform}\n"
                if source:
                    # Add source to content
                    chapter_tools_content += f"> **Available at:** <{source}>\n"
                # Remove yaml frontmatter from tool content
                tool_content = re.sub(r'---\n(.|\n)*?\n---\n', '', tool_content)
                # Add one nesting level to all headers
                tool_content = re.sub(r'^#', '##', tool_content, flags=re.MULTILINE)

                chapter_tools_content += '\n' + tool_content.strip()

        # Write the updated content to the file
        with tools_chapter_path.open('a') as f:
            content = chapter_tools_content + '\n'
            f.write(content)

def append_apps_as_subsections():
    base_document_path = Path('Document')
    base_apps_path = Path('apps')
    apps_chapter_path = base_document_path / '0x08b-Reference-Apps.md'
    
    for platform in ['android', 'ios']:
        chapter_apps_content = ""
        apps_path = base_apps_path / platform
        for app_file in apps_path.glob('*'):
            with app_file.open('r') as f:
                app_content = f.read()
                # Extract yaml frontmatter
                yaml_front = next(yaml.safe_load_all(app_content))
                # Extract title and source
                title = yaml_front['title']
                platform = yaml_front['platform']
                source = yaml_front.get('source')
                # Add title header to content
                chapter_apps_content += f"\n\n## {title}\n"
                chapter_apps_content += f"\n> **Platform:** {platform}\n"
                if source:
                    # Add source to content
                    chapter_apps_content += f"> **Available at:** <{source}>\n"
                # Remove yaml frontmatter from app content
                app_content = re.sub(r'---\n(.|\n)*?\n---\n', '', app_content)
                # Add one nesting level to all headers
                app_content = re.sub(r'^#', '##', app_content, flags=re.MULTILINE)

                chapter_apps_content += '\n' + app_content.strip()

        # Write the updated content to the file
        with apps_chapter_path.open('a') as f:
            content = chapter_apps_content + '\n'
            f.write(content)

def append_techniques_as_subsections():
    base_document_path = Path('Document')
    base_techniques_path = Path('techniques')
    android_techniques_chapter_path = base_document_path / '0x05b-Android-Security-Testing.md'
    ios_chapter_path = base_document_path / '0x06b-iOS-Security-Testing.md'
    
    for platform in ['android', 'ios']:
        chapter_techniques_content = ""
        techniques_path = base_techniques_path / platform
        for tool_file in techniques_path.glob('*'):
            with tool_file.open('r') as f:
                tool_content = f.read()
                # Extract yaml frontmatter
                yaml_front = next(yaml.safe_load_all(tool_content))
                # Extract title
                title = yaml_front['title']
                platform = yaml_front['platform']
                # Add title header to content
                chapter_techniques_content += f"\n\n## {title}\n"
                chapter_techniques_content += f"\n> **Platform:** {platform}\n"
                # Remove yaml frontmatter from tool content
                tool_content = re.sub(r'---\n(.|\n)*?\n---\n', '', tool_content)
                # Add one nesting level to all headers
                tool_content = re.sub(r'^#', '##', tool_content, flags=re.MULTILINE)

                chapter_techniques_content += '\n' + tool_content.strip()
        if platform == 'android':
            # Write the updated content to the file
            with android_techniques_chapter_path.open('a') as f:
                content = chapter_techniques_content + '\n'
                f.write(content)
        elif platform == 'ios':
            # Write the updated content to the file
            with ios_chapter_path.open('a') as f:
                content = chapter_techniques_content + '\n'
                f.write(content)

append_tests_as_subsections()

append_tools_as_subsections()

append_techniques_as_subsections()

append_apps_as_subsections()