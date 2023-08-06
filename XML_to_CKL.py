"""
File: STIG Online Form Integrated Editor (SOFIE)
Author: Jack McGowan & Nick Myers
Department: ITSD/ICS
Description: Code to automatically edit xml STIG files
"""
import xml.etree.ElementTree as ET
import re
import html
import uuid

FILENAME = ""
STIGNAME = ""
CLASS = "FOUO"
NUM_IDENTS = 0

def createUUID():
    return uuid.uuid4()

def postCorrection(FILENAME):
    with open("C:\\Users\\myersnd1\\Box\\SOFIE\\Code\\" + FILENAME + ".ckl", "r") as checklist:
        cklData = checklist.read()
        cklData = cklData.replace("�", "…")
        cklData = cklData.replace("&", "&amp;")
        attributeDatas = re.findall(r"<\s*ATTRIBUTE_DATA>(.*?)<\s*/ATTRIBUTE_DATA\s*", cklData, flags=re.S)
        for i in attributeDatas:
            n = i.replace(">", "&gt;")
            o = n.replace("<", "&lt;")
            cklData = cklData.replace(i, o)
    checklist = open("C:\\Users\\myersnd1\\Box\\SOFIE\\Code\\" + FILENAME + ".ckl", "wt")
    checklist.write(cklData)
    checklist.close()

def XMLpostCorrection(FILENAME):
    with open("C:\\Users\\myersnd1\\Box\\SOFIE\\Code\\STIGs\\" + FILENAME, "r", encoding="utf-8") as checklist:
        Data = checklist.read()
        Data = Data.replace("�", "…")
    checklist = open("C:\\Users\\myersnd1\\Box\\SOFIE\\Code\\STIGs\\" + FILENAME, "wt", encoding="utf-8")
    checklist.write(Data)
    checklist.close()

def xmlCorrection(STIGNAME):
    with open("C:\\Users\\myersnd1\\Box\\SOFIE\\Code\\STIGs\\" + STIGNAME, "r", encoding="utf-8") as stig:
        stigData = stig.read()
        stigData = stigData.replace("&lt;", "<").replace("&gt;", ">")
        #stigData = html.escape(STIGNAME)

        vulnDiscussions = re.findall(r"<\s*VulnDiscussion[^>]*>(.*?)</VulnDiscussion\s*", stigData, flags=re.S)
        fixTexts = re.findall(r"<\s*fixtext[^>]*>(.*?)</fixtext\s*", stigData, flags=re.S | re.M)
        checkContents = re.findall(r"<\s*check-content>(.*?)</check-content\s*", stigData, flags=re.S)
        for i in fixTexts:
            n = i.replace(">", "&gt;").replace("<", "&lt;")
            stigData = stigData.replace(i, n)

        for i in checkContents:
            #n = i.replace(">", "&gt;")
            #o = n.replace("<", "&lt;")
            o = html.escape(i)
            stigData = stigData.replace(i, o)
        for i in vulnDiscussions:
            #n = i.replace(">", "&gt;")
            #o = n.replace("<", "&lt;")
            o = html.escape(i)
            stigData = stigData.replace(i, o)

    XMLpostCorrection(STIGNAME)

    stig = open("C:\\Users\\myersnd1\\Box\\SOFIE\\Code\\STIGs\\" + STIGNAME, "wt", encoding="utf-8")
    stig.write(stigData)
    stig.close()

    found = False
    with open("C:\\Users\\myersnd1\\Box\\SOFIE\\Code\\STIGs\\" + STIGNAME, "r", encoding="utf-8") as stig:
        for line in stig:
            stripped_line = line.strip()
            if stripped_line.startswith('<plain-text id="release-info"'):
                newLine = stripped_line.replace('plain-text id="release-info"', 'release-info')
                newLine2 = newLine.replace('</plain-text>', '</release-info>')
                found = True
                break

    if found:
        stig = open("C:\\Users\\myersnd1\\Box\\SOFIE\\Code\\STIGs\\" + STIGNAME, "r", encoding="utf-8")
        stigdata2 = stig.read()
        stigdata2 = stigdata2.replace(stripped_line, newLine2)
        stig.close()

        stig = open("C:\\Users\\myersnd1\\Box\\SOFIE\\Code\\STIGs\\" + STIGNAME, "w", encoding="utf-8")
        stig.write(stigdata2)
        stig.close()

def checkWrite(value, f):
    if value is None:
        f.write("\n\t\t\t\t\t<ATTRIBUTE_DATA></ATTRIBUTE_DATA>")
    else:
        f.write("\n\t\t\t\t\t<ATTRIBUTE_DATA>" + value + "</ATTRIBUTE_DATA>")

def homeScreen(user_filename):
    global STIGNAME
    STIGNAME = "U_MS_Windows_10_STIG_V2R2_Manual-xccdf.xml"
    xmlCorrection(STIGNAME)
    parsedStig = ET.parse("C:\\Users\\myersnd1\\Box\\SOFIE\\Code\\STIGs\\" + STIGNAME)
    global FILENAME
    FILENAME = user_filename
    return parsedStig

def infoPage(parsedStig, f, the_uuid):
    '''
    global CLASS
    if classification == "Y":
        CLASS = "Class"
    else:
        CLASS = "Unclass"
    '''

    root = parsedStig.getroot()

    f.write('<?xml version="1.0" encoding="UTF-8"?>\n<!--DISA STIG Viewer :: 2.14-->\n<CHECKLIST>')
    f.write("\n\t<ASSET>")
    f.write("\n\t\t<ROLE></ROLE>")
    f.write("\n\t\t<ASSET_TYPE>Computing</ASSET_TYPE>")
    f.write("\n\t\t<HOST_NAME></HOST_NAME>")
    f.write("\n\t\t<HOST_IP></HOST_IP>")
    f.write("\n\t\t<HOST_MAC></HOST_MAC>")
    f.write("\n\t\t<HOST_FQDN></HOST_FQDN>")
    f.write("\n\t\t<TARGET_COMMENT></TARGET_COMMENT>")
    f.write("\n\t\t<TECH_AREA></TECH_AREA>")
    f.write("\n\t\t<TARGET_KEY>" + root.find("{http://checklists.nist.gov/xccdf/1.1}Group").find("{http://checklists.nist.gov/xccdf/1.1}Rule").find("{http://checklists.nist.gov/xccdf/1.1}reference").find("{http://purl.org/dc/elements/1.1/}identifier").text + "</TARGET_KEY>")
    f.write("\n\t\t<WEB_OR_DATABASE></WEB_OR_DATABASE>")
    f.write("\n\t\t<WEB_DB_SITE></WEB_DB_SITE>")
    f.write("\n\t\t<WEB_DB_INSTANCE></WEB_DB_INSTANCE>")
    f.write("\n\t</ASSET>")
    f.write("\n\t<STIGS>")
    f.write("\n\t\t<iSTIG>")
    f.write("\n\t\t\t<STIG_INFO>")

    for i in range(11):
        f.write("\n\t\t\t\t<SI_DATA>")
        if i == 0:
            f.write("\n\t\t\t\t\t<SID_NAME>version</SID_NAME>")
            f.write("\n\t\t\t\t\t<SID_DATA>" + root.find("{http://checklists.nist.gov/xccdf/1.1}version").text + "</SID_DATA>")
        elif i == 1:
            f.write("\n\t\t\t\t\t<SID_NAME>classification</SID_NAME>")
            f.write("\n\t\t\t\t\t<SID_DATA>UNCLASSIFIED//FOR OFFICIAL USE ONLY</SID_DATA>") #CHECK REAL STIG
        elif i == 2:
            f.write("\n\t\t\t\t\t<SID_NAME>customname</SID_NAME>")
        elif i == 3:
            f.write("\n\t\t\t\t\t<SID_NAME>stigid</SID_NAME>")
            f.write("\n\t\t\t\t\t<SID_DATA>" + root.get("id") + "</SID_DATA>")
        elif i == 4:
            f.write("\n\t\t\t\t\t<SID_NAME>description</SID_NAME>")
            Desc = root.find("{http://checklists.nist.gov/xccdf/1.1}description").text.strip()
            singleDesc = Desc.replace("\n       ", "")
            singleDesc = singleDesc.strip()
            f.write("\n\t\t\t\t\t<SID_DATA>" + singleDesc + "</SID_DATA>")
        elif i == 5:
            f.write("\n\t\t\t\t\t<SID_NAME>filename</SID_NAME>")
            f.write("\n\t\t\t\t\t<SID_DATA>" + STIGNAME + "</SID_DATA>")
        elif i == 6:
            f.write("\n\t\t\t\t\t<SID_NAME>releaseinfo</SID_NAME>")
            f.write("\n\t\t\t\t\t<SID_DATA>" + root.find("{http://checklists.nist.gov/xccdf/1.1}release-info").text + "</SID_DATA>")
        elif i == 7:
            f.write("\n\t\t\t\t\t<SID_NAME>title</SID_NAME>")
            f.write("\n\t\t\t\t\t<SID_DATA>" + root.find("{http://checklists.nist.gov/xccdf/1.1}title").text + "</SID_DATA>")
        elif i == 8:
            f.write("\n\t\t\t\t\t<SID_NAME>uuid</SID_NAME>")
            f.write("\n\t\t\t\t\t<SID_DATA>" + str(the_uuid) + "</SID_DATA>")
        elif i == 9:
            f.write("\n\t\t\t\t\t<SID_NAME>notice</SID_NAME>")
            f.write("\n\t\t\t\t\t<SID_DATA>" + root.find("{http://checklists.nist.gov/xccdf/1.1}notice").get("id") + "</SID_DATA>")
        elif i == 10:
            f.write("\n\t\t\t\t\t<SID_NAME>source</SID_NAME>")

        f.write("\n\t\t\t\t</SI_DATA>")

    f.write("\n\t\t\t</STIG_INFO>")
    return root

def sofie(root, f, the_uuid):
    for group in root.iter("{http://checklists.nist.gov/xccdf/1.1}Group"):
        f.write("\n\t\t\t<VULN>")
        for i in range(26):
            f.write("\n\t\t\t\t<STIG_DATA>")
            if i == 0:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>")
                checkWrite(group.get("id"), f)
            elif i == 1:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>")
                checkWrite(group.find("{http://checklists.nist.gov/xccdf/1.1}Rule").get("severity"), f)
            elif i == 2:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Group_Title</VULN_ATTRIBUTE>")
                checkWrite(group.find("{http://checklists.nist.gov/xccdf/1.1}title").text, f)
            elif i == 3:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE>")
                checkWrite(group.find("{http://checklists.nist.gov/xccdf/1.1}Rule").get("id"), f)
            elif i == 4:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE>")
                checkWrite(group.find("{http://checklists.nist.gov/xccdf/1.1}Rule").find("{http://checklists.nist.gov/xccdf/1.1}version").text, f)
            elif i == 5:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE>")
                longRuleTitle = group.find("{http://checklists.nist.gov/xccdf/1.1}Rule").find("{http://checklists.nist.gov/xccdf/1.1}title").text.strip()
                shortRuleTitle = longRuleTitle.replace("\n               ", "")
                checkWrite(shortRuleTitle, f)
            elif i == 6:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Vuln_Discuss</VULN_ATTRIBUTE>")
                longText = group.find("{http://checklists.nist.gov/xccdf/1.1}Rule").find("{http://checklists.nist.gov/xccdf/1.1}description").find("{http://checklists.nist.gov/xccdf/1.1}VulnDiscussion").text
                shortText = longText.replace("\n               ", "")
                checkWrite(shortText, f)
            elif i == 7:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>IA_Controls</VULN_ATTRIBUTE>")
                checkWrite(group.find("{http://checklists.nist.gov/xccdf/1.1}Rule").find("{http://checklists.nist.gov/xccdf/1.1}description").find("{http://checklists.nist.gov/xccdf/1.1}IAControls").text, f)
            elif i == 8:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Check_Content</VULN_ATTRIBUTE>")
                f.write("\n\t\t\t\t\t<ATTRIBUTE_DATA>")
                debug = re.findall(r"(?:\r?\n|^)((?:\r?\n|.)+?)(?=\r?\n\r?\n|$)", group[2].find("{http://checklists.nist.gov/xccdf/1.1}check").find("{http://checklists.nist.gov/xccdf/1.1}check-content").text, flags=re.S)
                for i in debug:
                    if i != debug[0]:
                        f.write("\n\n")
                    i = i.replace("                    ", "")

                    f.write(i.strip())
                f.write("</ATTRIBUTE_DATA>")
            elif i == 9:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Fix_Text</VULN_ATTRIBUTE>")
                f.write("\n\t\t\t\t\t<ATTRIBUTE_DATA>")
                debug = re.findall(r"(?:\r?\n|^)((?:\r?\n|.)+?)(?=\r?\n\r?\n|$)", group.find("{http://checklists.nist.gov/xccdf/1.1}Rule").find("{http://checklists.nist.gov/xccdf/1.1}fixtext").text, flags=re.S)
                for i in debug:
                    if i != debug[0]:
                        f.write("\n\n")
                    i = i.replace("                ", "")
                    i = i.replace("                 ", "")
                    f.write(i.strip())
                f.write("</ATTRIBUTE_DATA>")

            elif i == 10:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>False_Positives</VULN_ATTRIBUTE>")
                checkWrite(group.find("{http://checklists.nist.gov/xccdf/1.1}Rule").find("{http://checklists.nist.gov/xccdf/1.1}description").find("{http://checklists.nist.gov/xccdf/1.1}FalsePositives").text, f)
            elif i == 11:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>False_Negatives</VULN_ATTRIBUTE>")
                checkWrite(group.find("{http://checklists.nist.gov/xccdf/1.1}Rule").find("{http://checklists.nist.gov/xccdf/1.1}description").find("{http://checklists.nist.gov/xccdf/1.1}VulnDiscussion").text, f)
            elif i == 12:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Documentable</VULN_ATTRIBUTE>")
                checkWrite(group.find("{http://checklists.nist.gov/xccdf/1.1}Rule").find("{http://checklists.nist.gov/xccdf/1.1}description").find("{http://checklists.nist.gov/xccdf/1.1}Documentable").text, f)
            elif i == 13:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Mitigations</VULN_ATTRIBUTE>")
                checkWrite(group.find("{http://checklists.nist.gov/xccdf/1.1}Rule").find("{http://checklists.nist.gov/xccdf/1.1}description").find("{http://checklists.nist.gov/xccdf/1.1}Mitigations").text, f)
            elif i == 14:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Potential_Impact</VULN_ATTRIBUTE>")
                checkWrite(group.find("{http://checklists.nist.gov/xccdf/1.1}Rule").find("{http://checklists.nist.gov/xccdf/1.1}description").find("{http://checklists.nist.gov/xccdf/1.1}PotentialImpacts").text, f)
            elif i == 15:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Third_Party_Tools</VULN_ATTRIBUTE>")
                checkWrite(group.find("{http://checklists.nist.gov/xccdf/1.1}Rule").find("{http://checklists.nist.gov/xccdf/1.1}description").find("{http://checklists.nist.gov/xccdf/1.1}ThirdPartyTools").text, f)
            elif i == 16:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Mitigation_Control</VULN_ATTRIBUTE>")
                checkWrite(group.find("{http://checklists.nist.gov/xccdf/1.1}Rule").find("{http://checklists.nist.gov/xccdf/1.1}description").find("{http://checklists.nist.gov/xccdf/1.1}MitigationControl").text, f)
            elif i == 17:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Responsibility</VULN_ATTRIBUTE>")
                checkWrite(group.find("{http://checklists.nist.gov/xccdf/1.1}Rule").find("{http://checklists.nist.gov/xccdf/1.1}description").find("{http://checklists.nist.gov/xccdf/1.1}Responsibility").text, f)
            elif i == 18:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Security_Override_Guidance</VULN_ATTRIBUTE>")
                checkWrite(group.find("{http://checklists.nist.gov/xccdf/1.1}Rule").find("{http://checklists.nist.gov/xccdf/1.1}description").find("{http://checklists.nist.gov/xccdf/1.1}SeverityOverrideGuidance").text, f)
            elif i == 19:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Check_Content_Ref</VULN_ATTRIBUTE>")
                checkWrite(group.find("{http://checklists.nist.gov/xccdf/1.1}Rule").find("{http://checklists.nist.gov/xccdf/1.1}check").find("{http://checklists.nist.gov/xccdf/1.1}check-content-ref").get("name"), f)
            elif i == 20:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Weight</VULN_ATTRIBUTE>")
                checkWrite(group.find("{http://checklists.nist.gov/xccdf/1.1}Rule").get("weight"), f)
            elif i == 21:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>Class</VULN_ATTRIBUTE>") #CHECK REAL STIG
                checkWrite(CLASS, f)
            elif i == 22:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>STIGRef</VULN_ATTRIBUTE>")
                f.write("\n\t\t\t\t\t<ATTRIBUTE_DATA>" + root.find("{http://checklists.nist.gov/xccdf/1.1}title").text + " :: Version " + root.find("{http://checklists.nist.gov/xccdf/1.1}version").text + ", " + root.find("{http://checklists.nist.gov/xccdf/1.1}release-info").text + "</ATTRIBUTE_DATA>")
            elif i == 23:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>TargetKey</VULN_ATTRIBUTE>")
                checkWrite(group.find("{http://checklists.nist.gov/xccdf/1.1}Rule").find("{http://checklists.nist.gov/xccdf/1.1}reference").find("{http://purl.org/dc/elements/1.1/}identifier").text, f)
            elif i == 24:
                f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>STIG_UUID</VULN_ATTRIBUTE>")
                checkWrite(str(the_uuid), f)
            elif i == 25:
                size = 0
                legacyIDs = []
                for ident in group.iter("{http://checklists.nist.gov/xccdf/1.1}ident"):
                    legacyIDs.append(ident.text)
                    size += 1

                for id in legacyIDs:
                    if id.startswith("V") and legacyIDs.index(id) != 0:
                        temp = id
                        legacyIDs[legacyIDs.index(id)] = legacyIDs[0]
                        legacyIDs[0] = temp

                numIdent = 1
                for id in legacyIDs:
                    if numIdent != 1:
                        f.write("\n\t\t\t\t<STIG_DATA>")
                    if id.startswith("CCI"):
                        f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE>")
                    else:
                        f.write("\n\t\t\t\t\t<VULN_ATTRIBUTE>LEGACY_ID</VULN_ATTRIBUTE>")
                    checkWrite(id, f)
                    if size != numIdent:
                        f.write("\n\t\t\t\t</STIG_DATA>")
                    numIdent += 1

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

def XMLConversion(user_filename):
    the_uuid = createUUID()
    parsedStig = homeScreen(user_filename)
    f = open(FILENAME + ".ckl", "a")
    root = infoPage(parsedStig, f, the_uuid)
    sofie(root, f, the_uuid)
    postCorrection(FILENAME)