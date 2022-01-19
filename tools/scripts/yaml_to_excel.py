import yaml
from openpyxl import Workbook
from openpyxl.styles import PatternFill, Font
from openpyxl.styles.differential import DifferentialStyle
from openpyxl.drawing.image import Image
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.formatting.rule import Rule
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

STATUS_VALIDATION = DataValidation(type="list", formula1='"Pass,Fail,N/A"', allow_blank=True)

# Conditional Formatting for STATUS
red_text = Font(color="9C0006")
red_fill = PatternFill(bgColor="FFC7CE")
dxf = DifferentialStyle(font=red_text, fill=red_fill, alignment=excel_styles.align_center)
rule_fail = Rule(type="containsText", operator="containsText", text="Fail", dxf=dxf)
rule_fail.formula = ['NOT(ISERROR(SEARCH("Fail",J11)))']

green_text = Font(color="38761D")
green_fill = PatternFill(bgColor="B6D7A8")
dxf = DifferentialStyle(font=green_text, fill=green_fill, alignment=excel_styles.align_center)
rule_pass = Rule(type="containsText", operator="containsText", text="Pass", dxf=dxf)
rule_pass.formula = ['NOT(ISERROR(SEARCH("Pass",J11)))']

gray_text = Font(color="666666")
gray_fill = PatternFill(bgColor="CCCCCC")
dxf = DifferentialStyle(font=gray_text, fill=gray_fill, alignment=excel_styles.align_center)
rule_na = Rule(type="containsText", operator="containsText", text="N/A", dxf=dxf)
rule_na.formula = ['NOT(ISERROR(SEARCH("N/A",J11)))']


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

def get_hyperlink(url):

    if '/0x05' in url:
        title = 'Android'
    elif '/0x06' in url:
        title = 'iOS'
    return f'=HYPERLINK("{url}", "{title}")'


def write_table(masvs_file, output_file, mstg_version, mstg_commit, masvs_version, masvs_commit):

    masvs_dict = yaml.safe_load(open(masvs_file))

    wb = Workbook()

    table = wb.active
    table.title = 'Security Requirements'

    # table_config = {
    #     'start_row': 5,
    #     'start_col': 2,
    #     'columns': [
    #         {'name': 'ID', 'width': 10,},
    #         {'name': 'MSTG-ID', 'width': 25,},
    #         {'name': 'Detailed Verification Requirement',  'width': 80,},
    #         {'name': 'L1', 'style': 'blue', 'width': 5,},
    #         {'name': 'L2', 'style': 'green', 'width': 5,},
    #         {'name': 'R', 'style': 'orange', 'width': 5,},
    #         {'name': 'References', 'width': 70,},
    #     ]
            
    # }

    excel_styles.load_styles(wb)

    table.row_dimensions[2].height = 65
    table.merge_cells(start_row=2, end_row=4, start_column=2, end_column=3)

    img = Image('../../Document/Images/logo_circle.png')
    img.height = img.height * 0.15
    img.width = img.width * 0.15
    table.add_image(img, 'C2')

    img = Image('owasp-masvs/Document/images/OWASP_logo.png')
    img.height = img.height * 0.1
    img.width = img.width * 0.1
    table.add_image(img, 'H2')

    table['D2'].value = "Mobile Application Security Verification Standard"
    table['D2'].style = excel_styles.big_title

    table['D3'].value = f'=HYPERLINK("https://github.com/OWASP/owasp-mstg/releases/tag/{mstg_version}", "OWASP MSTG {mstg_version} (commit: {mstg_commit})")'
    table['D3'].font = Font(name=excel_styles.FONT, color="00C0C0C0")
    table['D4'].value = f'=HYPERLINK("https://github.com/OWASP/owasp-masvs/releases/tag/{masvs_version}", "OWASP MASVS {masvs_version} (commit: {masvs_commit})")'
    table['D4'].font = Font(name=excel_styles.FONT, color="00C0C0C0")

    table.column_dimensions['B'].width = 5
    table.column_dimensions['C'].width = 23
    table.column_dimensions['D'].width = 80
    table.column_dimensions['E'].width = 5
    table.column_dimensions['F'].width = 5
    table.column_dimensions['G'].width = 5
    table.column_dimensions['H'].width = 10
    table.column_dimensions['I'].width = 10
    table.column_dimensions['J'].width = 10

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
            
            category_cell = table.cell(row=row,column=col_id)
            category_cell.value = category_title
            category_cell.style = 'underline'
            category_cell.alignment = excel_styles.align_left

            table.merge_cells(start_row=row, end_row=row, start_column=col_id, end_column=col_status)

            table.row_dimensions[row].height = 25 # points
            row = row+2

            table.cell(row=row,column=col_id).value = 'ID'
            table.cell(row=row,column=col_id).style = 'gray_header'

            table.cell(row=row,column=col_mstg_id).value = 'MSTG-ID'
            table.cell(row=row,column=col_mstg_id).style = 'gray_header'
            
            table.cell(row=row,column=col_text).value = 'Control'
            table.cell(row=row,column=col_text).style = 'gray_header'

            table.cell(row=row,column=col_l1).value = 'L1'
            table.cell(row=row,column=col_l1).style = 'gray_header'
            table.cell(row=row,column=col_l2).value = 'L2'
            table.cell(row=row,column=col_l2).style = 'gray_header'
            table.cell(row=row,column=col_r).value = 'R'
            table.cell(row=row,column=col_r).style = 'gray_header'

            table.cell(row=row,column=col_link_android).value = 'MSTG Test Coverage'
            table.cell(row=row,column=col_link_android).style = 'gray_header'
            table.merge_cells(start_row=row, end_row=row, start_column=col_link_android, end_column=col_link_ios)

            table.cell(row=row,column=col_status).value = 'Status'
            table.cell(row=row,column=col_status).style = 'gray_header'
            table.add_data_validation(STATUS_VALIDATION)

            row = row + 2

        # End header

        table.cell(row=row,column=col_id).value = req['id']
        table.cell(row=row,column=col_id).style = 'center'

        table.cell(row=row,column=col_mstg_id).value = mstg_id
        table.cell(row=row,column=col_mstg_id).style = 'center'
        
        table.cell(row=row,column=col_text).value = req['text']
        table.cell(row=row,column=col_text).style = 'text'
        
        if req['L1']:
            table.cell(row=row,column=col_l1).style = 'blue'
        if req['L2']:
            table.cell(row=row,column=col_l2).style = 'green'
        if req['R']:
            table.cell(row=row,column=col_r).style = 'orange'
        if req.get('links'):
            table.cell(row=row,column=col_link_android).value = get_hyperlink(req['links'][0])
            table.cell(row=row,column=col_link_android).style = 'center'
            if len(req['links']) >= 2:
                table.cell(row=row,column=col_link_ios).value = get_hyperlink(req['links'][1])
                table.cell(row=row,column=col_link_ios).style = 'center'
        else:
            table.cell(row=row,column=col_link_android).value = 'N/A'
            table.cell(row=row,column=col_link_android).style = 'gray_header'
            table.cell(row=row,column=col_link_ios).value = 'N/A'
            table.cell(row=row,column=col_link_ios).style = 'gray_header'
            
        table.row_dimensions[row].height = 55 # points

        status_cell = table.cell(row=row,column=col_status).coordinate
        STATUS_VALIDATION.add(status_cell)
        table.conditional_formatting.add(status_cell, rule_fail)
        table.conditional_formatting.add(status_cell, rule_pass)
        table.conditional_formatting.add(status_cell, rule_na)

        row = row+1

    table.sheet_view.showGridLines = False

    wb.save(filename=output_file)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Export the MASVS requirements as Excel. Default language is en.')
    parser.add_argument('-m', '--masvs', required=True)
    parser.add_argument('-o', '--outputfile', required=True)
    parser.add_argument('-v1', '--mstgversion', required=True)
    parser.add_argument('-c1', '--mstgcommit', required=True)
    parser.add_argument('-v2', '--masvsversion', required=True)
    parser.add_argument('-c2', '--masvscommit', required=True)

    args = parser.parse_args()

    print(f"Generating Checklist for MSTG {args.mstgversion} ({args.mstgcommit}) and MASVS {args.masvsversion} ({args.masvscommit})")

    write_table(args.masvs, args.outputfile, args.mstgversion, args.mstgcommit, args.masvsversion, args.masvscommit)


if __name__ == '__main__':
    main()