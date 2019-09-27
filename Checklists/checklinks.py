import xlrd
loc = ("Mobile_App_Security_Checklist-English_1.1.xlsx")
wb = xlrd.open_workbook(loc)
sheet = wb.sheet_by_index(2) # SecReq Android
#for i in range(1, 80):
#    print(sheet.cell_value(i, 6)) # row , col
#print(sheet.hyperlink_list)

for row_index in range(1, sheet.nrows):
    URL = sheet.hyperlink_map.get((row_index, 1))
    print(URL)


# https://xlrd.readthedocs.io/en/latest/api.html
