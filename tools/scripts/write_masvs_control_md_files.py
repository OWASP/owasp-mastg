import os
import combine_data_for_checklist
import excel_styles_and_validation as mas_styles

masvs_v2 = combine_data_for_checklist.retrieve_masvs()

for group in masvs_v2['groups']:

    for control in group['controls']:
        content = f'# {control["id"]}\n\n'
        content += f'<p style="font-size: 2em">{control["statement"]}</p>\n\n'
        # add html thick separation line in blue 
        content += f'<hr style="height: 0.2em; background-color: #{mas_styles.MAS_BLUE}; border: 0;" />\n\n'
        content += f'{control["description"]}\n'

        with open(os.path.join('docs/MASVS/controls', f'{control["id"]}.md'), 'w') as f:
            f.write(content)