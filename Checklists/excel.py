import xlsxwriter

# NOT WORKING

# Create a new workbook and add a worksheet
workbook = xlsxwriter.Workbook('Mobile_App_Security_Checklist-English_1.1.xlsx')

for worksheet in workbook.worksheets():
    print(worksheet.get_name())

worksheet = workbook.get_worksheet_by_name('Security Requirements - Android')

# Add a sample alternative link format.
red_format = workbook.add_format({
    'font_color': 'red',
    'bold':       1,
    'underline':  1,
    'font_size':  12,
})

# Write some hyperlinks
worksheet.write_url('G16', 'http://www.python.org/', string='Python Home')
#worksheet.write_url('A5', 'http://www.python.org/', tip='Click here')
# worksheet.write_url('A7', 'http://www.python.org/', red_format)

workbook.close()