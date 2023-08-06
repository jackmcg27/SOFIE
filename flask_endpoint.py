import xml.etree.ElementTree as ET
import os
from flask import Flask, flash, redirect, render_template, request, send_file
from werkzeug.utils import secure_filename
import pandas as pd
import CSV_to_CKL
import datetime

CHECKLIST_FOLDER = 'C:\\Users\\mcgow\\OneDrive\\Documents\\APL\\SOFIE\\SOFIEWebV2\\checklists\\'
POSSIBLE_STIG_LIST = 'C:\\Users\\mcgow\\OneDrive\\Documents\\APL\\SOFIE\\SOFIEWebV2\\STIG_Name_Translation.csv'
ALL_STIGS = 'C:\\Users\\myersnd1\\Desktop\\2021_Q3_ALLSTIGS.csv'
ALLOWED_EXTENSIONS = {'ckl'}
FILENAME = ""
ROOT = ""
PARSEDCKL = ""
VULN_NUMS = []

# construct the flask app
app = Flask(__name__)
app.config['CHECKLIST_FOLDER'] = CHECKLIST_FOLDER
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.lstrip_blocks = True
app.jinja_env.trim_blocks = True


@app.route('/')
def index():
    """
    The landing page
    :return: HTML
    """
    return render_template('Welcome.html')


@app.route('/empty_stig', methods=['GET', 'POST'])
def empty_stig():
    """
    :return: HTML
    """
    global VULN_NUMS
    VULN_NUMS = []
    category = ""


    STIG_Categories = []

    if request.method == 'POST':
        category = request.form.get('fCategory')
        if request.form.get('fdevice-app') != None:
            global FILENAME
            FILENAME = request.form.get('ffileName')
            CSV_to_CKL.CSVConversion(FILENAME, request.form.get('fdevice-app'))
            return redirect('/empty_stig/info')

    STIGcsvList = removeOldSTIGS()

    for i in range(len(STIGcsvList)):
        for j in range(len(STIGcsvList[i])):
            STIGcsvList[i][j] = str(STIGcsvList[i][j]).strip()
        if (STIGcsvList[i][2] + ' / ' + STIGcsvList[i][3]) not in STIG_Categories:
            STIG_Categories.append(str(STIGcsvList[i][2]) + ' / ' + str(STIGcsvList[i][3]))
    STIG_Categories = sorted(STIG_Categories)
    if 'nan / nan' in STIG_Categories:
        nanIndex = STIG_Categories.index("nan / nan")
        STIG_Categories[nanIndex] = "Other"
    return render_template('empty_stig_home.html', category=category, STIG_Categories=STIG_Categories,
                           categoryCount=len(STIG_Categories), STIGcsvList=STIGcsvList, STIGcount=len(STIGcsvList))


@app.route('/empty_stig/info', methods=['GET', 'POST'])
def empty_stig_info():
    """
        Auto fills text fields/drop downs with existing system information
        :return: HTML
        """
    global ROOT
    global PARSEDCKL
    global CHECKLIST_FOLDER
    if request.method == "POST":
        quest.form.get('fhostname')
        ROOT.find("ASSET").find("HOST_IP").text = request.form.get('ip')
        ROOT.find("ASSET").find("ROLE").text = request.form.get('fsystem_role')
        ROOT.find("ASSET").find("WEB_OR_DATABASE").text = request.form.get('fweb')
        PARSEDCKL.write(CHECKLIST_FOLDER + FILENAME + ".ckl",
                        short_empty_elements=False)
        if request.form.get('fhostname') == "" or request.form.get('ip') == "" or request.form.get(
                'fsystem_role') == 'None':
            return redirect('/empty_stig/info')
        elif not ipValidate(request.form.get('ip')):
            return redirect('/empty_stig/inROOT.find("ASSET").find("HOST_NAME").text = refo')
        return redirect('/empty_stig/info/editor/' + ROOT.find('STIGS').find('iSTIG')[1][0][1].text)

    if request.method == "GET":
        PARSEDCKL = ET.parse(CHECKLIST_FOLDER + FILENAME + ".ckl")
        ROOT = PARSEDCKL.getroot()
        hostname = ROOT.find("ASSET").find("HOST_NAME").text
        ipAddress = ROOT.find("ASSET").find("HOST_IP").text
        systemRole = ROOT.find("ASSET").find("ROLE").text
        web = ROOT.find("ASSET").find("WEB_OR_DATABASE").text

    return render_template('enter_stig_info.html', hostname=hostname, ipAddress=ipAddress, systemRole=systemRole,
                           web=web)


@app.route('/empty_stig/info/editor/<vulnerability>', methods=['GET', 'POST'])
def empty_stig_info_editor(vulnerability):
    """
    Displays vulnerability ID numbers and their status
    :return: HTML
    """

    global VULN_NUMS
    global CHECKLIST_FOLDER
    vulnCount = len(ROOT.find('STIGS').find('iSTIG'))
    vulnStatus = []
    countNR = 0
    countO = 0
    countNF = 0
    countNA = 0
    catIOpen = 0
    incorrectVuln = []

    for j in range(1, vulnCount):
        fakestatus = ROOT.find('STIGS').find('iSTIG')[j]
        status = fakestatus.find('STATUS').text
        if status == 'Not_Reviewed':
            vulnStatus.append('NR')
            countNR += 1
        elif status == 'Open':
            vulnStatus.append('O')
            countO += 1
        elif status == 'NotAFinding':
            vulnStatus.append('NF')
            countNF += 1
        elif status == "Not_Applicable":
            vulnStatus.append('NA')
            countNA += 1

    for i in range(1, vulnCount):
        route = ROOT.find('STIGS').find('iSTIG')[i]
        if route[1][1].text == 'high' and vulnStatus[i - 1] == 'O':
            catIOpen += 1

    VULN_NUMS = []
    for i in range(1, vulnCount):
        VULN_NUMS.append(ROOT.find('STIGS').find('iSTIG')[i][0][1].text)

    for i in range(1, vulnCount):
        route = ROOT.find('STIGS').find('iSTIG')[i]
        if not commentsValidation(route.find('FINDING_DETAILS').text, route.find('STATUS').text):
            incorrectVuln.append(VULN_NUMS[i - 1])
        if not commentsValidation(route.find('COMMENTS').text, route.find('STATUS').text) and VULN_NUMS[
            i - 1] not in incorrectVuln:
            incorrectVuln.append(VULN_NUMS[i - 1])

    if request.method == 'POST':
        vulnIndex = VULN_NUMS.index(vulnerability) + 1
        vulnCKLroute = ROOT.find("STIGS").find("iSTIG")[vulnIndex]
        vulnCKLroute.find('STATUS').text = request.form.get('fstatus')
        vulnCKLroute.find('SEVERITY_OVERRIDE').text = request.form.get('fsevOverride')
        vulnCKLroute.find('FINDING_DETAILS').text = request.form.get('fFINDING_DETAILS')
        vulnCKLroute.find('COMMENTS').text = request.form.get('fCOMMENTS')
        PARSEDCKL.write(CHECKLIST_FOLDER + FILENAME + ".ckl",
                        short_empty_elements=False)
        if request.form.get('vulnId'):
            return redirect('/empty_stig/info/editor/' + request.form.get('vulnId'))

        if request.form.get('downloadButton'):
            if len(incorrectVuln) > 0:
                return redirect('/empty_stig/info/editor/' + vulnerability)
            return send_file(CHECKLIST_FOLDER + FILENAME + ".ckl")
        return redirect('/empty_stig/info/editor/' + vulnerability)

    if request.method == 'GET':
        # VULN_NUMS = []
        # for i in range(1, vulnCount):
        #    VULN_NUMS.append(ROOT.find('STIGS').find('iSTIG')[i][0][1].text)
        vulnIndex = VULN_NUMS.index(vulnerability)
        vulnCKLroute = ROOT.find("STIGS").find("iSTIG")[vulnIndex + 1]
        origSeverity = vulnCKLroute[1][1].text
        origStatus = vulnCKLroute.find('STATUS').text
        if vulnCKLroute.find('FINDING_DETAILS') == None:
            origFindingDet = ""
        else:
            origFindingDet = vulnCKLroute.find('FINDING_DETAILS').text
        if vulnCKLroute.find('COMMENTS') == None:
            origComments = ""
        else:
            origComments = vulnCKLroute.find('COMMENTS').text
        ruleTitle = vulnCKLroute[5][1].text
        discussion = vulnCKLroute[6][1].text
        checkText = vulnCKLroute[8][1].text
        checkTextList = checkText.split('\n')
        fixText = vulnCKLroute[9][1].text
        fixTextList = fixText.split('\n')
        incorrectVulnLength = len(incorrectVuln)
        return render_template('empty_stig_info_editor.html', VULN_NUMS=VULN_NUMS, vulnStatus=vulnStatus,
                               vulnCount=vulnCount - 1, origStatus=origStatus, origSeverity=origSeverity,
                               findingDet=origFindingDet, comments=origComments, file=FILENAME, ruleTitle=ruleTitle,
                               discussion=discussion, checkText=checkTextList, fixText=fixTextList, vulnIndex=vulnIndex,
                               countNR=countNR, countO=countO, countNA=countNA, countNF=countNF, catIOpen=catIOpen,
                               incorrectVuln=incorrectVuln, incorrectVulnLength=incorrectVulnLength)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/import_stig', methods=['GET', 'POST'])
def import_stig():
    """
    Imports an existing checklist file
    :return: HTML
    """
    global CHECKLIST_FOLDER
    global FILENAME
    if request.method == 'POST':
        # check if the post request has the file part
        if 'checklist' not in request.files:
            flash('No file part')
            return redirect(request.url)
        checklist = request.files['checklist']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if checklist.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if checklist and allowed_file(checklist.filename):
            FILENAME = secure_filename(checklist.filename)
            checklist.save(os.path.join(app.config['CHECKLIST_FOLDER'], FILENAME))
            return redirect('/import_stig/info')

    return render_template('import_stig_home.html')


@app.route('/import_stig/info', methods=['GET', 'POST'])
def import_stig_info():
    """
    Auto fills text fields/drop downs with existing system information
    :return: HTML
    """
    global ROOT
    global PARSEDCKL
    global CHECKLIST_FOLDER
    if request.method == "POST":
        ROOT.find("ASSET").find("HOST_NAME").text = request.form.get('fhostname')
        ROOT.find("ASSET").find("HOST_IP").text = request.form.get('ip')
        ROOT.find("ASSET").find("ROLE").text = request.form.get('fsystem_role')
        ROOT.find("ASSET").find("WEB_OR_DATABASE").text = request.form.get('fweb')
        PARSEDCKL.write(CHECKLIST_FOLDER + FILENAME, short_empty_elements=False)
        if request.form.get('fhostname') == "" or request.form.get('ip') == "" or request.form.get(
                'fsystem_role') == 'None':
            return redirect('/import_stig/info')
        return redirect('/import_stig/info/editor/' + ROOT.find('STIGS').find('iSTIG')[1][0][1].text)

    if request.method == "GET":
        PARSEDCKL = ET.parse(CHECKLIST_FOLDER + FILENAME)
        ROOT = PARSEDCKL.getroot()
        hostname = ROOT.find("ASSET").find("HOST_NAME").text
        ipAddress = ROOT.find("ASSET").find("HOST_IP").text
        systemRole = ROOT.find("ASSET").find("ROLE").text
        web = ROOT.find("ASSET").find("WEB_OR_DATABASE").text

    return render_template('enter_stig_info.html', hostname=hostname, ipAddress=ipAddress, systemRole=systemRole,
                           web=web)


@app.route('/import_stig/info/editor/<vulnerability>', methods=['GET', 'POST'])
def import_stig_info_editor(vulnerability):
    """
    Displays vulnerability ID numbers and their status
    :return: HTML
    """
    global VULN_NUMS
    global CHECKLIST_FOLDER
    vulnCount = len(ROOT.find('STIGS').find('iSTIG'))
    vulnStatus = []
    countNR = 0
    countO = 0
    countNF = 0
    countNA = 0
    catIOpen = 0
    incorrectVuln = []

    for j in range(1, vulnCount):
        fakestatus = ROOT.find('STIGS').find('iSTIG')[j]
        status = fakestatus.find('STATUS').text
        if status == 'Not_Reviewed':
            vulnStatus.append('NR')
            countNR += 1
        elif status == 'Open':
            vulnStatus.append('O')
            countO += 1
        elif status == 'NotAFinding':
            vulnStatus.append('NF')
            countNF += 1
        elif status == "Not_Applicable":
            vulnStatus.append('NA')
            countNA += 1

    for i in range(1, vulnCount):
        route = ROOT.find('STIGS').find('iSTIG')[i]
        if route[1][1].text == 'high' and vulnStatus[i - 1] == 'O':
            catIOpen += 1

    VULN_NUMS = []
    for i in range(1, vulnCount):
        VULN_NUMS.append(ROOT.find('STIGS').find('iSTIG')[i][0][1].text)

    for i in range(1, vulnCount):
        route = ROOT.find('STIGS').find('iSTIG')[i]
        if not commentsValidation(route.find('FINDING_DETAILS').text, route.find('STATUS').text):
            incorrectVuln.append(VULN_NUMS[i - 1])
        if not commentsValidation(route.find('COMMENTS').text, route.find('STATUS').text) and VULN_NUMS[
            i - 1] not in incorrectVuln:
            incorrectVuln.append(VULN_NUMS[i - 1])

    if request.method == 'POST':
        vulnIndex = VULN_NUMS.index(vulnerability) + 1
        vulnCKLroute = ROOT.find("STIGS").find("iSTIG")[vulnIndex]
        vulnCKLroute.find('STATUS').text = request.form.get('fstatus')
        vulnCKLroute.find('SEVERITY_OVERRIDE').text = request.form.get('fsevOverride')
        vulnCKLroute.find('FINDING_DETAILS').text = request.form.get('fFINDING_DETAILS')
        vulnCKLroute.find('COMMENTS').text = request.form.get('fCOMMENTS')
        PARSEDCKL.write(CHECKLIST_FOLDER + FILENAME,
                        short_empty_elements=False)

        if request.form.get('vulnId'):
            return redirect('/import_stig/info/editor/' + request.form.get('vulnId'))
        if request.form.get('downloadButton'):
            if len(incorrectVuln) > 0:
                return redirect('/import_stig/info/editor/' + vulnerability)
            return send_file(CHECKLIST_FOLDER + FILENAME)
        return redirect('/import_stig/info/editor/' + vulnerability)

    if request.method == 'GET':
        vulnIndex = VULN_NUMS.index(vulnerability)
        vulnCKLroute = ROOT.find("STIGS").find("iSTIG")[vulnIndex + 1]
        origSeverity = vulnCKLroute[1][1].text
        origStatus = vulnCKLroute.find('STATUS').text
        if vulnCKLroute.find('FINDING_DETAILS') == None:
            origFindingDet = ""
        else:
            origFindingDet = vulnCKLroute.find('FINDING_DETAILS').text
        if vulnCKLroute.find('COMMENTS') == None:
            origComments = ""
        else:
            origComments = vulnCKLroute.find('COMMENTS').text
        ruleTitle = vulnCKLroute[5][1].text
        discussion = vulnCKLroute[6][1].text
        checkText = vulnCKLroute[8][1].text
        checkTextList = checkText.split('\n')
        fixText = vulnCKLroute[9][1].text
        fixTextList = fixText.split('\n')
        incorrectVulnLength = len(incorrectVuln)
        return render_template('import_stig_info_editor.html', VULN_NUMS=VULN_NUMS, vulnStatus=vulnStatus,
                               vulnCount=vulnCount - 1, origStatus=origStatus, origSeverity=origSeverity,
                               findingDet=origFindingDet, comments=origComments, file=FILENAME, ruleTitle=ruleTitle,
                               discussion=discussion, checkText=checkTextList, fixText=fixTextList, vulnIndex=vulnIndex,
                               countNR=countNR, countO=countO, countNA=countNA, countNF=countNF, catIOpen=catIOpen,
                               incorrectVuln=incorrectVuln, incorrectVulnLength=incorrectVulnLength)


def ipValidate(ipAddress):
    splitIP = ipAddress.split('.')
    validNums = '0123456789'
    if len(splitIP) != 4:
        return False
    for i in range(len(splitIP)):
        if splitIP[i] == '':
            return False
        for char in splitIP[i]:
            if char not in validNums:
                return False
        if int(splitIP[i]) > 255:
            return False
    if ipAddress == '127.0.0.1':
        return False
    return True


def commentsValidation(comments, status):
    fullDate = datetime.datetime.now()
    year = fullDate.strftime("%Y")
    month = fullDate.strftime("%m")
    if status == 'NotAFinding':
        status = 'Not A Finding'
    else:
        status = status.replace('_', ' ')
    if comments == None:
        return False
    if comments[0:4] == str(year) or comments[0:4] == str(int(year) - 1):
        if comments[5:7] == str(month) or comments[5:7] == str(int(month) - 1) or comments[5:7] == str(int(month) - 2):
            if status.lower() in comments.lower() and status != 'Not Reviewed':
                return True
    return False


def removeOldSTIGS():
    allSTIGS = pd.read_csv(ALL_STIGS)
    allSTIGSList = allSTIGS.values.tolist()
    STIGcsv = pd.read_csv(POSSIBLE_STIG_LIST)
    STIGcsvList = STIGcsv.values.tolist()

    drop = False

    for i in range(len(STIGcsvList)):
        for j in range(len(allSTIGSList)):
            if str(STIGcsvList[i][1]) not in str(allSTIGSList[j][21]):
                drop = True
            else:
                drop = False
                break
        if drop:
            STIGcsv.drop(i, axis=0, inplace=True)
    STIGcsv.to_csv(POSSIBLE_STIG_LIST, index=False)
    del allSTIGSList
    del allSTIGS
    STIGcsv = pd.read_csv(POSSIBLE_STIG_LIST)
    STIGcsvList = STIGcsv.values.tolist()
    del STIGcsv
    return STIGcsvList


if __name__ == '__main__':
    app.run(host='127.0.0.1')
