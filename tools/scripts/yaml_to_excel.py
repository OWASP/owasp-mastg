import yaml
from openpyxl import Workbook
from openpyxl.styles import Font
from openpyxl.drawing.image import Image

import excel_styles

''' Tool for exporting the MASVS requirements as a checklist including MSTG coverage.

    By Carlos Holguera

    Copyright (c) 2022 OWASP Foundation

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

'''

# TODO parametrize & create a function
# TODO read sheet, col ids and cell styles (centered, left, colored, character if true, etc) from yaml

MASVS_TITLES = {
    'V1': 'Architecture, Design and Threat Modeling Requirements',
    'V2': 'Data Storage and Privacy Requirements',
    'V3': 'Cryptography Requirements',
    'V4': 'Authentication and Session Management Requirements',
    'V5': 'Network Communication Requirements',
    'V6': 'Platform Interaction Requirements',
    'V7': 'Code Quality and Build Setting Requirements',
    'V8': 'Resilience Requirements',
}

MSTGVERSION = ""
MSTGCOMMIT = ""
MASVSVERSION = ""
MASVSCOMMIT = ""

# def get_hyperlink(url):

#     if '/0x05' in url:
#         title = 'Android'
#     elif '/0x06' in url:
#         title = 'iOS'
#     return f'=HYPERLINK("{url}", "{title}")'

def write_header(ws):

    ws.row_dimensions[2].height = 65
    ws.merge_cells(start_row=2, end_row=4, start_column=2, end_column=3)

    img = Image('../../Document/Images/logo_circle.png')
    img.height = img.height * 0.15
    img.width = img.width * 0.15
    ws.add_image(img, 'C2')

    img = Image('owasp-masvs/Document/images/OWASP_logo.png')
    img.height = img.height * 0.1
    img.width = img.width * 0.1
    ws.add_image(img, 'H2')

    ws['D2'].value = "Mobile Application Security Verification Standard"
    ws['D2'].style = 'big_title'

    ws['D3'].value = f'=HYPERLINK("https://github.com/OWASP/owasp-mstg/releases/tag/{MSTGVERSION}", "OWASP MSTG {MSTGVERSION} (commit: {MSTGCOMMIT})")'
    ws['D3'].font = Font(name=excel_styles.FONT, color="00C0C0C0")
    ws['D4'].value = f'=HYPERLINK("https://github.com/OWASP/owasp-masvs/releases/tag/{MASVSVERSION}", "OWASP MASVS {MASVSVERSION} (commit: {MASVSCOMMIT})")'
    ws['D4'].font = Font(name=excel_styles.FONT, color="00C0C0C0")

def create_about_sheet(wb):
    ws = wb.create_sheet("About")
    write_header(ws)

def write_table(masvs_file, output_file):

    masvs_dict = yaml.safe_load(open(masvs_file))

    wb = Workbook()
    excel_styles.load_styles(wb)

    ws = wb.active
    ws.title = 'Security Requirements'

    write_header(ws)

    # ws_config = {
    #     'start_row': 6,
    #     'start_col': 2,
    #     'columns': [
    #         {'col': 'B', position: 2, 'name': 'ID', 'width': 10,},
    #         {'col': 'C', position: 3, 'name': 'MSTG-ID', 'width': 25,},
    #         {'col': 'D', position: 4, 'name': 'Detailed Verification Requirement',  'width': 80,},
    #         {'col': 'E', position: 5, 'name': 'L1', 'style': 'blue', 'width': 5,},
    #         {'col': 'F', position: 6, 'name': 'L2', 'style': 'green', 'width': 5,},
    #         {'col': 'G', position: 7, 'name': 'R', 'style': 'orange', 'width': 5,},
    #         {'col': 'H', position: 8, 'name': 'Android', 'width': 10,},
    #         {'col': 'I', position: 9, 'name': 'iOS', 'width': 10,},
    #         {'col': 'J', position: 10, 'name': 'Status', 'width': 10,},
    #     ]
            
    # }

    ws.column_dimensions['B'].width = 5
    ws.column_dimensions['C'].width = 23
    ws.column_dimensions['D'].width = 80
    ws.column_dimensions['E'].width = 5
    ws.column_dimensions['F'].width = 5
    ws.column_dimensions['G'].width = 5
    ws.column_dimensions['H'].width = 10
    ws.column_dimensions['I'].width = 10
    ws.column_dimensions['J'].width = 10

    row=6
    col_id=2
    col_mstg_id=3
    col_text=4
    col_l1=5
    col_l2=6
    col_r=7
    col_link_android=8
    col_link_ios=9
    col_status=10

    for mstg_id, req in masvs_dict.items():
        req_id = req['id'].split('.') 
        category = req_id[0]
        subindex = req_id[1]

        if subindex == '1':
            row = row+1

            category_id = f"V{category}"
            category_title = MASVS_TITLES[category_id]
            
            category_cell = ws.cell(row=row,column=col_id)
            category_cell.value = category_title
            category_cell.style = 'underline'
            category_cell.alignment = excel_styles.align_left

            ws.merge_cells(start_row=row, end_row=row, start_column=col_id, end_column=col_status)

            ws.row_dimensions[row].height = 25 # points
            row = row+2

            ws.cell(row=row,column=col_id).value = 'ID'
            ws.cell(row=row,column=col_id).style = 'gray_header'

            ws.cell(row=row,column=col_mstg_id).value = 'MSTG-ID'
            ws.cell(row=row,column=col_mstg_id).style = 'gray_header'
            
            ws.cell(row=row,column=col_text).value = 'Control'
            ws.cell(row=row,column=col_text).style = 'gray_header'

            ws.cell(row=row,column=col_l1).value = 'L1'
            ws.cell(row=row,column=col_l1).style = 'gray_header'
            ws.cell(row=row,column=col_l2).value = 'L2'
            ws.cell(row=row,column=col_l2).style = 'gray_header'
            ws.cell(row=row,column=col_r).value = 'R'
            ws.cell(row=row,column=col_r).style = 'gray_header'

            ws.cell(row=row,column=col_link_android).value = 'Android'
            ws.cell(row=row,column=col_link_android).style = 'gray_header'
            ws.cell(row=row,column=col_link_ios).value = 'iOS'
            ws.cell(row=row,column=col_link_ios).style = 'gray_header'

            ws.cell(row=row,column=col_status).value = 'Status'
            ws.cell(row=row,column=col_status).style = 'gray_header'
            ws.add_data_validation(excel_styles.status_validation)

            row = row + 2

        # End header

        ws.cell(row=row,column=col_id).value = req['id']
        ws.cell(row=row,column=col_id).style = 'center'

        ws.cell(row=row,column=col_mstg_id).value = mstg_id
        ws.cell(row=row,column=col_mstg_id).style = 'center'
        
        ws.cell(row=row,column=col_text).value = req['text']
        ws.cell(row=row,column=col_text).style = 'text'
        
        if req['L1']:
            ws.cell(row=row,column=col_l1).style = 'blue'
        if req['L2']:
            ws.cell(row=row,column=col_l2).style = 'green'
        if req['R']:
            ws.cell(row=row,column=col_r).style = 'orange'
        if req.get('links'):
            ws.cell(row=row,column=col_link_android).value = f"=HYPERLINK('{req['links'][0]}', 'Open')"
            ws.cell(row=row,column=col_link_android).style = 'center'
            if len(req['links']) >= 2:
                ws.cell(row=row,column=col_link_ios).value = f"=HYPERLINK('{req['links'][1]}', 'Open')"
                ws.cell(row=row,column=col_link_ios).style = 'center'
        else:
            ws.cell(row=row,column=col_link_android).value = 'N/A'
            ws.cell(row=row,column=col_link_android).style = 'gray_header'
            ws.cell(row=row,column=col_link_ios).value = 'N/A'
            ws.cell(row=row,column=col_link_ios).style = 'gray_header'
            
        ws.row_dimensions[row].height = 55 # points

        status_cell = ws.cell(row=row,column=col_status).coordinate
        excel_styles.status_validation.add(status_cell)
        ws.conditional_formatting.add(status_cell, excel_styles.rule_fail)
        ws.conditional_formatting.add(status_cell, excel_styles.rule_pass)
        ws.conditional_formatting.add(status_cell, excel_styles.rule_na)

        row = row+1

    ws.sheet_view.showGridLines = False

    create_about_sheet(wb)
    wb.save(filename=output_file)

def main():
    global MSTGVERSION, MSTGCOMMIT, MASVSVERSION, MASVSCOMMIT
    import argparse
    
    parser = argparse.ArgumentParser(description='Export the MASVS requirements as Excel. Default language is en.')
    parser.add_argument('-m', '--masvs', required=True)
    parser.add_argument('-o', '--outputfile', required=True)
    parser.add_argument('-v1', '--mstgversion', required=True)
    parser.add_argument('-c1', '--mstgcommit', required=True)
    parser.add_argument('-v2', '--masvsversion', required=True)
    parser.add_argument('-c2', '--masvscommit', required=True)

    args = parser.parse_args()

    MSTGVERSION = args.mstgversion
    MSTGCOMMIT = args.mstgcommit
    MASVSVERSION = args.masvsversion
    MASVSCOMMIT = args.masvscommit

    print(f"Generating Checklist for MSTG {MSTGVERSION} ({MSTGCOMMIT}) and MASVS {MASVSVERSION} ({MASVSCOMMIT})")

    write_table(args.masvs, args.outputfile)


if __name__ == '__main__':
    main()