import os
import re
import yaml

def split_md_file(input_file):
    # Read in the input file
    with open(input_file, 'r') as f:
        input_text = f.read()
    
    # Split the input text into sections based on level 2 headings
    sections = re.split(r'^###\s(.+)', input_text, flags=re.MULTILINE)
    sections.pop(0)  # Remove the initial empty string
    
    # Create a directory to store the output files
    dirname = os.path.splitext(input_file)[0]
    if not os.path.exists(dirname):
        os.mkdir(dirname)
    
    # Loop over the sections and write each one to a separate file
    for i in range(0, len(sections), 2):
        section_title = sections[i].strip()
        section_content = sections[i+1].strip()
        
        # Create the filename for the output file
        filename = f"{dirname}/TOOL-{i//2+1:04d}.md"
        
        # Create the YAML frontmatter header with the section title
        frontmatter = {'title': section_title}
        yaml_text = yaml.dump(frontmatter, default_flow_style=False)
        
        # Write the output file
        with open(filename, 'w') as f:
            f.write(f"---\n{yaml_text}---\n\n{section_content}")
    
    print(f"Split {input_file} into {len(sections)//2} output files.")

split_md_file("../Document/0x08a-Testing-Tools.md")
