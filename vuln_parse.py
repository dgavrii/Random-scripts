# -*- coding: utf-8 -*-
"""
Spyder Editor

"""

import csv

def menu():
    print('*****************MENU*****************')
    print()
    run_prog = True
    while run_prog == True:
        choice = input("""Please choose from the following options:
            
                       -ch will print a list of the column headers in the input file
                       -vs will print a list of the unique vulnerability signatures, and the associated count
                       -ks will ask for a keyword to search for, then return a list of the signatures that include
                       the keyword, along with the associated count
                       -os will print known OS associated with vulnerabilities, and the associated count
                       -cve will print a list of all unique CVE values in the file, and the associated count of each
                       -w will take one of the above inputs and write the results into a specified CSV file
                       -q will exit the program
                       
                       Please enter your choice: """)
        print("You chose: " + choice)
        
        if choice == '-ch':
            print(list_col_headers())
        elif choice == '-vs':
            print(create_keyword_dict())
        elif choice == '-ks':
            print(keyword_vuln_desc())
        elif choice == '-os':
            print(readOS())
        elif choice == '-cve':
            print(readCVEInfo())
        elif choice == '-q':
            print("You are now exiting the program.")
            break
        elif choice == '-w':
            file = input("What is the file path of the CSV you would like to write to? ")
    #        data = ""
            value_input = input("""What function output would you like to write to the CSV? Please 
                         choose from the following options:
                             -ch will print a list of the column headers in the input file
                             -vs will print a list of the unique vulnerability signatures, and the associated count
                             -ks will ask for a keyword to search for, then return a list of the signatures that include 
                             the keyword, along with the associated count
                             -os will print known OS associated with vulnerabilities, and the associated count
                             -cve will print a list of all unique CVE values in the file, and the associated count of each
                             -q will exit the program
                             
                             Please enter your choice: """)
            print("You chose to write the values from: " + value_input + " into the specified CSV file.")
            if value_input == '-ch':
                data = list_col_headers()
            elif value_input == '-vs':
                data = create_keyword_dict()
            elif value_input == '-ks':
                data = keyword_vuln_desc()
            elif value_input == '-os':
                data = readOS()
            elif value_input == '-cve':
                data = readCVEInfo()
            elif value_input == '-q':
                print("You are now exiting the program.")
                break
            else:
                return "That is not a valid entry."
                
            file_path = r'{file}'.format(file=file)
            writeFile(file_path, data)
            print("You wrote the results from the function {function} to the file located at '{path}'. ".format(function=value_input,path=file))
       
        else:
            print("That was not a valid choice. Please ensure the '-' character is included in your selection, and the selection is from the above menu. ")
            
#-----------------------------------------------------------------------
#This path will need to be updated to match the local directory where this script is run
vulns_csv_path = r'C:\Users\brittanyalexander\Documents\Misc\Edited_KTech_Vulns_Sample_Set.csv'
outputs_csv_path = r'C:\Users\brittanyalexander\Documents\Misc\Outputs.csv'
#-----------------------------------------------------------------------
#List of keywords to parse for in the "Signature" field
keywords = ['Microsoft', 'Symantec', 'Remote Code Execution', 'Cached Logon', 
            'Bypass', 'DLL Preloading', 'Header Not Detected']
#-----------------------------------------------------------------------
#Taking in the column headers and adding them to a list - useful when column headers 
#aren't static values and will need to be referenced, like in the functions below.

#this is associated with the "-ch" input
def list_col_headers(path=vulns_csv_path):
    with open(vulns_csv_path, 'r') as csv_file:
        csv_reader = csv.reader((x.replace('\0', '') for x in csv_file), delimiter=',')
        headers = ''
        line_count = 0
        for row in csv_reader:
            if line_count == 0:
                headers += str(row)
                line_count += 1
        return headers

#-----------------------------------------------------------------------
#this is associated with the "-vs" input
def create_keyword_dict(path=vulns_csv_path):
    with open(path, 'r') as csv_file:
        csv_reader = csv.DictReader((x.replace('\0', '') for x in csv_file),delimiter = ',')
#        line_count = 0
        keyword_count = {}
        key_column_name = 'Signature'
        for row in csv_reader: 
            if key_column_name in row.keys():
                for keyword in keywords:
                    if keyword in row[key_column_name] and keyword in keyword_count.keys():
                        keyword_count[keyword] += 1
                    elif keyword in row[key_column_name] and keyword not in keyword_count.keys():
                        keyword_count[keyword] = 1
            else:
                return "Key not found"
        return keyword_count
 
#create_keyword_dict()
#   Output: {'Microsoft': 143, 'Remote Code Execution': 51, 'Symantec': 62, 'DLL Preloading': 31, 
#           'Bypass': 31, 'Cached Logon': 31, 'Header Not Detected': 16}

#-----------------------------------------------------------------------
#Returns full vulnerability description for "Signatures" that include a given keyword,
#and the count of times that vulnerability description appears. For now, they keywords 
#being searched for will be taken from user input
        
#this is associated with the "-ks" input

def keyword_vuln_desc(path=vulns_csv_path):
    with open(path, 'r') as csv_file:
        csv_reader = csv.DictReader((x.replace('\0', '') for x in csv_file),delimiter = ',')
        key_column_name = 'Signature'
        get_input = input("What term would you like to search for? ")
        search_word = get_input
        keyword_vulns = {}
        for row in csv_reader: 
            if key_column_name in row.keys():
                if search_word in row[key_column_name]:
                    if row[key_column_name] not in keyword_vulns.keys():
                        keyword_vulns[(row[key_column_name])] = 1
                    else:
                        keyword_vulns[(row[key_column_name])] += 1
                else:
                    continue
        return keyword_vulns
        for key in keyword_vulns.keys():
            print("There are {num} {vuln} vulnerabilities.".format(num = keyword_vulns[key], vuln = key))

#print(keyword_vuln_desc())

#-----------------------------------------------------------------------
#Creates a dictionary of the known OS related to each vulnerability; returns a count of the OS

#this is associated with the "-os" input
def readOS(path=vulns_csv_path):
    f = open(path, 'r')
    csv_reader = csv.DictReader((x.replace('\0', '') for x in f),delimiter = ',')
    data = {}
    key_column_name = 'OS'
    for row in csv_reader:
        if key_column_name in row.keys():
            if row[key_column_name] not in data.keys():
                data[(row[key_column_name])] = 1
            elif row[key_column_name] in data.keys():
                data[(row[key_column_name])] += 1
    return data
  
#print(readOS())
    #Output of the above function:
    #{'Microsoft Windows Server 2012 R2 Standard': 279, 'Windows 2012 behind 
    #F5 Networks Big-IP': 1, 'Windows Vista / Windows 2008 behind F5 Networks Big-IP': 2, 
    #'F5 Networks Big-IP': 29}

#-----------------------------------------------------------------------
#Creates a dictionary of all unique CVEs included in the dataset; returns a count of how often  
#each CVE appears in the dataset.
    
#this is associated with the "-cve" input
def readCVEInfo(path=vulns_csv_path):
    f = open(path, 'r')
    csv_reader = csv.DictReader((x.replace('\0', '') for x in f),delimiter = ',')
    cve_values = []
    cve_values_split = []
    cve_count = {}
    key_column_name = 'CVE'
    for row in csv_reader:
        if key_column_name in row.keys():
            if row[key_column_name] != '':
                cve_values.append(row[key_column_name])
            else:
                continue
    for item in cve_values:
        new_item = item.split(",")
        for cve in new_item:
            cve_clean = cve.strip()
            cve_values_split.append(cve_clean)
    for cve in cve_values_split:
        if cve not in cve_count.keys():
            cve_count[cve] = 1
        elif cve in cve_count.keys():
            cve_count[cve] +=1
    return cve_count
    
#print(readCVEInfo())
    #Yields the below output: 
    #{'CVE-2015-1761': 21, 'CVE-2015-1762': 21, 'CVE-2015-1763': 21, 'CVE-2018-12245': 31, 
    #'CVE-2018-12238': 31, 'CVE-2018-12239': 31, 'CVE-2018-8653': 30, 'CVE-2018-8619': 30, 
    #'CVE-2018-8625': 30, 'CVE-2018-8631': 30, 'CVE-2018-8643': 30, 'CVE-2018-8517': 30, 
    #'CVE-2018-8540': 30, 'CVE-2018-8477': 30, 'CVE-2018-8514': 30, 'CVE-2018-8595': 30, 
    #'CVE-2018-8641': 30, 'CVE-2018-8649': 30, 'CVE-2018-8596': 30, 'CVE-2018-8599': 30, 
    #'CVE-2018-8611': 30, 'CVE-2018-8612': 30, 'CVE-2018-8621': 30, 'CVE-2018-8622': 30, 
    #'CVE-2018-8626': 30, 'CVE-2018-8634': 30, 'CVE-2018-8637': 30, 'CVE-2018-8638': 30, 
    #'CVE-2018-8639': 30, 'CVE-2018-3639': 1, 'CVE-2018-8552': 1, 'CVE-2018-8570': 1, 
    #'CVE-2016-2183': 2, 'CVE-2004-0790': 1, 'CVE-2004-0791': 1, 'CVE-2004-1060': 1, 
    #'CVE-2003-1418': 1}
    #This aligns with the counts in the CSV sample file


#-----------------------------------------------------------------------
##Takes in values from one of the above functions (needs to be passed in via the "data" 
##argument) and writes the key:value pairs from each dictionary into a blank CSV file
##that is specified as the argument "outFile" - Note: the outfile must exist already,
##and will be defined using the "outputs_csv_path" variable at the top of this script.
 
#this is associated with the "-write" input           
def writeFile(outFile, data):
    with open(outFile, 'w') as csv_file:
        fieldnames = ['field_value','count']
#        print(fieldnames)
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        
        writer.writeheader()
        for key in data.keys():
            writer.writerow({'field_value': key, 'count': data[key]})
#        return writer

#print(writeFile(outputs_csv_path, create_keyword_dict()))

menu()
