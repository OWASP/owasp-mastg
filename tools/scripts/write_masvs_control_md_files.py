import os
import combine_data_for_checklist

masvs_v2 = combine_data_for_checklist.retrieve_masvs()

for group in masvs_v2['groups']:

    for control in group['controls']:
        content = f'# {control["id"]}\n\n'
        content += f'!!! success ""\n    **Control:** {control["statement"]}\n\n'
        content += f'{control["description"]}\n'

        with open(os.path.join('docs/MASVS/controls', f'{control["id"]}.md'), 'w') as f:
            f.write(content)