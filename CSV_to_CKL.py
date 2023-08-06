"""
File: STIG Online Form Integrated Editor (SOFIE)
Author: Jack McGowan & Nick Myers
Department: ITSD/ICS
Description: Code to convert STIG data in a CSV file to a ckl file
"""

import pandas as pd
import re
import uuid

CHECKLIST_FOLDER = "C:\\Users\\myersnd1\\Box\\SOFIE\\SOFIEWebV2\\checklists\\"
FILENAME = ""
CLASS = "FOUO"
NUM_IDENTS = 0
MIN_VULN = 0
MAX_VULN = 0

def createUUID():
    return uuid.uuid4()

def postCorrection(user_filename):
    with open(CHECKLIST_FOLDER + user_filename + ".ckl", "r", encoding='UTF-8') as checklist:
        cklData = checklist.read()
        cklData = cklData.replace("�", "…")
        cklData = cklData.replace("&", "&amp;")
        attributeDatas = re.findall(r"<\s*ATTRIBUTE_DATA>(.*?)<\s*/ATTRIBUTE_DATA\s*", cklData, flags=re.S)
        for i in attributeDatas:
            n = i.replace(">", "&gt;")
            o = n.replace("<", "&lt;")
            cklData = cklData.replace(i, o)
    checklist = open(CHECKLIST_FOLDER + user_filename + ".ckl", "wt", encoding='UTF-8')
    checklist.write(cklData)
    checklist.close()


def checkWrite(value, f):
    if value is None or value == 'nan':
        f.write("\n\t\t\t\t\t<ATTRIBUTE_DATA></ATTRIBUTE_DATA>")
    else:
        f.write("\n\t\t\t\t\t<ATTRIBUTE_DATA>" + value + "</ATTRIBUTE_DATA>")


def storeCSVData():
    csvFile = "C:\\Users\\myersnd1\\Desktop\\2021_Q3_ALLSTIGS.csv"
    CSVData = pd.read_csv(csvFile)
    return CSVData


def infoPage(csvData, f, the_uuid, chosenStig):
    '''
    global CLASS
    if classification == "Y":
        CLASS = "Class"
    else:
        CLASS = "Unclass"
    '''

    csvDataList = csvData.values.tolist()
    firstInstance = True
    global MIN_VULN
    global MAX_VULN
    for i in range(len(csvDataList)):
        if chosenStig in str(csvDataList[i][21]):
            if firstInstance:
                MIN_VULN = i
                firstInstance = False
            MAX_VULN = i
    f.write('<?xml version="1.0" encoding="UTF-8"?>\n<!--DISA STIG Viewer :: 2.14-->\n<CHECKLIST>')
    f.write("\n\t<ASSET>")
    f.write("\n\t\t<ROLE>None</ROLE>")
    f.write("\n\t\t<ASSET_TYPE>Computing</ASSET_TYPE>")
    f.write("\n\t\t<HOST_NAME></HOST_NAME>")
    f.write("\n\t\t<HOST_IP></HOST_IP>")
    f.write("\n\t\t<HOST_MAC></HOST_MAC>")
    f.write("\n\t\t<HOST_FQDN></HOST_FQDN>")
    f.write("\n\t\t<TARGET_COMMENT></TARGET_COMMENT>")
    f.write("\n\t\t<TECH_AREA></TECH_AREA>")
    f.write("\n\t\t<TARGET_KEY>" + str(csvDataList[MIN_VULN][22]) + "</TARGET_KEY>")
    f.write("\n\t\t<WEB_OR_DATABASE>false</WEB_OR_DATABASE>")
    f.write("\n\t\t<WEB_DB_SITE></WEB_DB_SITE>")
    f.write("\n\t\t<WEB_DB_INSTANCE></WEB_DB_INSTANCE>")
    f.write("\n\t</ASSET>")
    f.write("\n\t<STIGS>")
    f.write("\n\t\t<iSTIG>")
    f.write("\n\t\t\t<STIG_INFO>")

    for i in range(0, 11):
        stigid = str(csvDataList[MIN_VULN][21]).split(' Security Technical Implementation Guide')
        realStigID = stigid[0].replace(" ", "_")
        f.write("\n\t\t\t\t<SI_DATA>")
        if i == 0:
            f.write("\n\t\t\t\t\t<SID_NAME>version</SID_NAME>")
            version = str(csvDataList[MIN_VULN][21]).split('Version ')
            actualVersion = version[1][0]
            f.write("\n\t\t\t\t\t<SID_DATA>" + actualVersion + "</SID_DATA>")
        elif i == 1:
            f.write("\n\t\t\t\t\t<SID_NAME>classification</SID_NAME>")
            f.write("\n\t\t\t\t\t<SID_DATA>UNCLASSIFIED//FOR OFFICIAL USE ONLY</SID_DATA>")
        elif i == 2:
            f.write("\n\t\t\t\t\t<SID_NAME>customname</SID_NAME>")
        elif i == 3:
            f.write("\n\t\t\t\t\t<SID_NAME>stigid</SID_NAME>")
            f.write("\n\t\t\t\t\t<SID_DATA>" + realStigID + "</SID_DATA>")
        elif i == 4:
            f.write("\n\t\t\t\t\t<SID_NAME>description</SID_NAME>")
            f.write("\n\t\t\t\t\t<SID_DATA>This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via mail to the following address: disa.stig_spt@mail.mil.</SID_DATA>")
        elif i == 5:
            f.write("\n\t\t\t\t\t<SID_NAME>filename</SID_NAME>")
            f.write("\n\t\t\t\t\t<SID_DATA>" + realStigID + ".xml</SID_DATA>")
        elif i == 6:
            f.write("\n\t\t\t\t\t<SID_NAME>releaseinfo</SID_NAME>")
            f.write("\n\t\t\t\t\t<SID_DATA>" + (csvDataList[MIN_VULN][21].split(', '))[1] + "</SID_DATA>")
        elif i == 7:
            f.write("\n\t\t\t\t\t<SID_NAME>title</SID_NAME>")
            f.write("\n\t\t\t\t\t<SID_DATA>" + (csvDataList[MIN_VULN][21].split(' ::'))[0] + "</SID_DATA>")
        elif i == 8:
            f.write("\n\t\t\t\t\t<SID_NAME>uuid</SID_NAME>")
            f.write("\n\t\t\t\t\t<SID_DATA>" + str(the_uuid) + "</SID_DATA>")
        elif i == 9:
            f.write("\n\t\t\t\t\t<SID_NAME>notice</SID_NAME>")
            f.write("\n\t\t\t\t\t<SID_DATA>terms-of-use</SID_DATA>")
        elif i == 10:
            f.write("\n\t\t\t\t\t<SID_NAME>source</SID_NAME>")
        f.write("\n\t\t\t\t</SI_DATA>")
    f.write("\n\t\t\t</STIG_INFO>")
    return csvDataList


def sofie(csvDataList, f, the_uuid):
    for j in range(MIN_VULN, MAX_VULN + 1):
        f.write("\n\t\t\t<VULN>")
        for i in range(26):
            f.write("\n\t\t\t\t<STIG_DATA>")
            if i == 0:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][0]), f)
            elif i == 1:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][1]), f)
            elif i == 2:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Group_Title</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][2]), f)
            elif i == 3:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][3]), f)
            elif i == 4:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][4]), f)
            elif i == 5:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][5]), f)
            elif i == 6:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Vuln_Discuss</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][6]), f)
            elif i == 7:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>IA_Controls</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][7]), f)
            elif i == 8:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Check_Content</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][8]), f)
            elif i == 9:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Fix_Text</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][9]), f)
            elif i == 10:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>False_Positives</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][10]), f)
            elif i == 11:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>False_Negatives</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][11]), f)
            elif i == 12:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Documentable</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][12]).lower(), f)
            elif i == 13:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Mitigations</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][13]), f)
            elif i == 14:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Potential_Impact</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][14]), f)
            elif i == 15:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Third_Party_Tools</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][15]), f)
            elif i == 16:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Mitigation_Control</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][16]), f)
            elif i == 17:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Responsibility</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][17]), f)
            elif i == 18:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Security_Override_Guidance</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][18]), f)
            elif i == 19:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Check_Content_Ref</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][19]), f)
            elif i == 20:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Weight</VULN_ATTRIBUTE>")
                f.write("\n\t\t\t\t\t<ATTRIBUTE_DATA>10.0</ATTRIBUTE_DATA>")
            elif i == 21:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Class</VULN_ATTRIBUTE>")  # CHECK REAL STIG
                checkWrite(CLASS, f)
            elif i == 22:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>STIGRef</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][21]), f)
            elif i == 23:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>TargetKey</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][22]), f)
            elif i == 24:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>STIG_UUID</VULN_ATTRIBUTE>")
                checkWrite(str(the_uuid), f)
            elif i == 25:
                legacyIDs = str(csvDataList[j][25]).split('; ')

                for k in range(len(legacyIDs)):
                    if k != 0:
                        f.write("\n\t\t\t\t<STIG_DATA>")
                    f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>LEGACY_ID</VULN_ATTRIBUTE>")
                    checkWrite(legacyIDs[k], f)
                    f.write("\n\t\t\t\t</STIG_DATA>")
                f.write("\n\t\t\t\t<STIG_DATA>")
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE>")
                checkWrite(str(csvDataList[j][23]).split('\n')[0], f)

            f.write("\n\t\t\t\t</STIG_DATA>")
        f.write("\n\t\t\t\t<STATUS>Not_Reviewed</STATUS>")
        f.write("\n\t\t\t\t<FINDING_DETAILS></FINDING_DETAILS>")
        f.write("\n\t\t\t\t<COMMENTS></COMMENTS>")
        f.write("\n\t\t\t\t<SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>")
        f.write("\n\t\t\t\t<SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>")
        f.write("\n\t\t\t</VULN>")
    f.write("\n\t\t</iSTIG>")
    f.write("\n\t</STIGS>")
    f.write("\n</CHECKLIST>")


def CSVConversion(user_filename, chosenStig):
    the_uuid = createUUID()
    CSVData = storeCSVData()
    f = open(CHECKLIST_FOLDER + user_filename + ".ckl", "a", encoding='UTF-8')
    csvDataList = infoPage(CSVData, f, the_uuid, chosenStig)
    sofie(csvDataList, f, the_uuid)
    f.close()
    postCorrection(user_filename)
