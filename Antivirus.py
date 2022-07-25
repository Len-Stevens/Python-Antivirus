# imports
from PyQt5 import QtCore, QtGui, QtWidgets
from virustotal_python import Virustotal
import configparser
import webbrowser
import threading
import requests
import hashlib
import time
import sys
import os

# get current directory
current_dir         = (os.path.dirname(__file__))

# Hashes path
HASH_Files          = (current_dir + '/hard_signatures/')

# settings.ini file path
settings_file_path  = (current_dir + '/settings/settings.ini')

# get log file
LOG_file            = (current_dir + '/logs/log.txt')

# define Stuff
VERSION             = "2.9"
DEV                 = "cookie0_o, Len-Stevens, MandiYang"

# url´s
Report_issues       = "https://github.com/Len-Stevens/Python-Antivirus/issues/new"
Submit_sample       = "https://github.com/Len-Stevens/Python-Antivirus/discussions/8"
virus_total_api     = "https://www.virustotal.com/api/v3/files/report"
meta_defender_api   = "https://api.metadefender.com/v4/hash/" # + hash


# define config
config = configparser.ConfigParser()
config.read(settings_file_path)


# clear log file
with open(LOG_file, 'r+') as f:
    f.truncate(0)
    f.close()

Title_template      = f"""\
                    PY-Antivirus [v{VERSION}]
            DEV: {DEV} 
##############################LOGS##############################\n"""

def LOG(LOG):
    # open log file
    with open(LOG_file, "a") as log_file:
        # write error to log file
        log_file.write(LOG+"")
        log_file.close()
    return
LOG(Title_template)



def Get_Hashes(self, MainWindow):
    try:
        # check if hashes are already downloaded
        with open(HASH_Files + "/md5-Hashes_pack1.txt", "r") as f:
            f.close()
        return
    except:
        pass
    try:

        # change tab to loading
        self.Tabs.setCurrentIndex(1)

        # get 1 hash pack
        x = requests.get("https://virusshare.com/hashfiles/VirusShare_00000.md5")
        # get 2 hash pack
        y = requests.get("https://virusshare.com/hashfiles/VirusShare_00001.md5")
        # get 3 hash pack
        z = requests.get("https://virusshare.com/hashfiles/VirusShare_00002.md5")

        # get all hashes

        # save hashes to file
        with open(HASH_Files+"/md5-Hashes_pack1.txt", "w") as f:
            f.write(x.text)
            f.close()

        with open(HASH_Files+"/md5-Hashes_pack2.txt", "w") as f:
            f.write(y.text)
            f.close()

        with open(HASH_Files+"/md5-Hashes_pack3.txt", "w") as f:
            f.write(z.text)
            f.close()

        return
    
    except Exception as e:
        # error when getting zip file or unpacking it
        # open log file
        LOG("-ERROR ;\n")
        LOG(str(e)+ "\n")
        # show error message
        msgBox = QtWidgets.QMessageBox()
        msgBox.setIcon(QtWidgets.QMessageBox.Critical)
        msgBox.setText("Error")
        msgBox.setInformativeText(f"""\
Error when downloading hashes check if your internet connection is working.
App will now close.
        """)
        # remove window title bar
        msgBox.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)
        msgBox.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        msgBox.exec_()
        exit()
        return
   


# save settings to settings/settings.ini
def SaveSettings(self):
    # get api keys
    api_key = self.VirusTotalApiKey.text()
    MetaDefenderApiKey = self.MetaDefenderApiKey.text()
    # get VirusTotal scan checkbox status and meta defender scan checkbox status
    virus_total_scan = self.UseVirusTotalApiCheckBox.isChecked()
    meta_defender_scan = self.UseMetaDefenderApiCheckBox.isChecked()
    self.VirusTotalApiKey.setText(api_key)

    config['-settings-']['VirusTotalScan'] = str(virus_total_scan)
    config['-settings-']['VirusTotalApiKey'] = str(api_key)
    config["-settings-"]["MetaDefenderScan"] = str(meta_defender_scan)
    config["-settings-"]["MetaDefenderApiKey"] = str(MetaDefenderApiKey)
    if self.LightModeButton.text() == "Light Mode":
        config["-settings-"]["Style"] = "Dark"
    else:
        config["-settings-"]["Style"] = "Light"

    with open(settings_file_path, 'w') as configfile: # save
        config.write(configfile)

    return

    
# remove file
def removeFile(file):
    try:
        os.remove(file)
        return

    except Exception as e:
        # open log file
        LOG("-ERROR ;\n")
        LOG(str(e)+ "\n")
        return

class RESULTS():
    # display results
    def displayResults_VIRUS(self, file):
        self.Tabs.setCurrentIndex(2)
        # check if virus total check if on and file is under 32mb
        if self.UseVirusTotalApiCheckBox.isChecked() and os.path.getsize(file) < 32000000:
            self.VirusTotalWidget.show()
        else:
            # hide Virus total results since it is not needed
            self.VirusTotalWidget.hide()
        if self.UseMetaDefenderApiCheckBox.isChecked():
            self.MetaDefenderWidget.show()
        else:
            # hide meta defender results since it is not needed
            self.MetaDefenderWidget.hide()
            self.IsFileVirusY_N.setStyleSheet("color: red")
            self.IsFileVirusY_N.setText("YES!")
        # delete file button
        self.DeleteFileButton.clicked.connect(lambda: removeFile(file))
        # return button
        self.ReturnToHomeTabButton.clicked.connect(lambda: self.Tabs.setCurrentIndex(0))


    def displayResults_CLEAN(self, file):
        self.Tabs.setCurrentIndex(2)
        # check if virus total check if on and file is under 32mb
        if self.UseVirusTotalApiCheckBox.isChecked() and os.path.getsize(file) < 32000000:
            self.VirusTotalWidget.show()
        else:
            # hide Virus total results since it is not needed
            self.VirusTotalWidget.hide()
        if self.UseMetaDefenderApiCheckBox.isChecked():
            self.MetaDefenderWidget.show()
        else:
            # hide meta defender results since it is not needed
            self.MetaDefenderWidget.hide()
            # set text to clean
            self.IsFileVirusY_N.setStyleSheet("color: green")
            self.IsFileVirusY_N.setText("NO!")
        # delete file button
        self.DeleteFileButton.clicked.connect(lambda: removeFile(file))
        # return button
        self.ReturnToHomeTabButton.clicked.connect(lambda: self.Tabs.setCurrentIndex(0))

class FILE_SCAN():
    def scan(file, self, MainWindow):
        # default virus found to false
        virus_found = False

        # get Virus hashes
        SHA256_HASHES_pack1 = (HASH_Files + '/md5-Hashes_pack1.txt')
        SHA256_HASHES_pack2 = (HASH_Files + '/md5-Hashes_pack2.txt')
        SHA256_HASHES_pack3 = (HASH_Files + '/md5-Hashes_pack3.txt')

        try:
            # open file and get hash
            with open(file,"rb") as target_file:
                bytes = target_file.read()
                readable_hash = hashlib.md5(bytes).hexdigest()
            # display hash
            self.FileHash.setText("File Hash:  " + readable_hash)
            # close file
            target_file.close()


            # SHA256 HASHES check + pack 1
            with open(SHA256_HASHES_pack1,'r') as pack1:
                for line in pack1:
                    # skip first 6 lines
                    if line.startswith("#"):
                        pass
                    else:
                        # read lines and check if hash is in file
                        if readable_hash in line:
                            virus_found = True
                        if not readable_hash in line:
                            pass
                else:
                    pack1.close()


            if virus_found == False:
                # SHA256 HASHES check + pack 2
                with open(SHA256_HASHES_pack2,'r') as pack2:
                    for line in pack2:
                        # skip first 6 lines
                        if line.startswith("#"):
                            pass
                        else:
                            # read lines and check if hash is in file
                            if readable_hash in line:
                                virus_found = True
                            if not readable_hash in line:
                                pass
                    else:
                        pack2.close()


            if virus_found == False:
                # SHA256 HASHES check + pack 3
                with open(SHA256_HASHES_pack3,'r') as pack3:
                    for line in pack3:
                        # skip first 6 lines
                        if line.startswith("#"):
                            pass
                        else:
                            # read lines and check if hash is in file
                            if readable_hash in line:
                                virus_found = True
                            if not readable_hash in line:
                                pass
                    else:
                        pack3.close()

            


            try:
                # check if Virus total api is checked and file is under 32mb then scan the file with Virus total
                if self.UseVirusTotalApiCheckBox.isChecked() and os.path.getsize(file) < 32000000:
                    # get api key
                    api_key = self.VirusTotalApiKey.text()
                    # check if api key is empty if yes then show error
                    if api_key == "":
                        msgBox = QtWidgets.QMessageBox()
                        msgBox.setIcon(QtWidgets.QMessageBox.Critical)
                        msgBox.setText("Error")
                        msgBox.setInformativeText(f"""\
        Please enter a valid Virus Total API key.
                        """)
                        # remove window title bar
                        msgBox.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)
                        msgBox.setWindowFlags(QtCore.Qt.FramelessWindowHint)
                        msgBox.exec_()
                    # if api key is not empty then scan the file
                    else:
                        # Create dictionary containing the file to send for multipart encoding upload
                        files = {"file": (os.path.basename(file), open(os.path.abspath(file), "rb"))}

                        vtotal = Virustotal(API_KEY=api_key)
                        resp = vtotal.request("files", files=files, method="POST")
                        id = resp.data["id"]
                        headers = {"x-apikey": api_key}
                        analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{id}", headers=headers)
                        analysis_json = analysis.json()
                        detections = analysis_json["data"]["attributes"]["stats"]["malicious"]
                        not_detections = analysis_json["data"]["attributes"]["stats"]["undetected"]
                        # show Virus total results
                        self.VirusTotalWidget.show()
                        # if detections more than half of not detections print red
                        if detections > not_detections:
                            self.DetectionsText.setStyleSheet("color: red")
                            self.DetectionsText.setText(f"{str(detections)}")
                            if virus_found == False:
                                self.IsFileVirusY_N.setFont(QtGui.QFont("Arial", 10))
                                self.IsFileVirusY_N.setText("Probably a virus!")
                            else:
                                RESULTS.displayResults_VIRUS(self, file)
                        else:
                            self.DetectionsText.setStyleSheet("color: green")
                            self.DetectionsText.setText(f"{str(detections)}")
                            if virus_found == False:
                                self.IsFileVirusY_N.setStyleSheet("color: green")
                                self.IsFileVirusY_N.setFont(QtGui.QFont("Arial", 12))
                                self.IsFileVirusY_N.setText("Probably clean")
                            else:
                                RESULTS.displayResults_VIRUS(self, file)
                else:
                    pass
            
            # show error when virus total api was not able to scan the file
            except Exception as e:
                # set results to ERROR
                self.DetectionsText.setStyleSheet("color: red")
                self.DetectionsText.setText("ERROR")

                # open log file
                LOG("-ERROR ;\n")
                LOG(str(e)+ "\n")

                # show error box
                msgBox = QtWidgets.QMessageBox()
                msgBox.setIcon(QtWidgets.QMessageBox.Critical)
                msgBox.setText("Error")
                msgBox.setInformativeText(f"""\
         Cant scan file with Virus Total.
                """)
                # remove window title bar
                msgBox.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)
                msgBox.setWindowFlags(QtCore.Qt.FramelessWindowHint)
                msgBox.exec_()

            try:
                # Meta Defender hash check
                if self.UseMetaDefenderApiCheckBox.isChecked():
                    # get api key
                    MetaDefenderApiKey = self.MetaDefenderApiKey.text()
                    # check if api key is empty if yes then show error
                    if MetaDefenderApiKey == "":
                        msgBox = QtWidgets.QMessageBox()
                        msgBox.setIcon(QtWidgets.QMessageBox.Critical)
                        msgBox.setText("Error")
                        msgBox.setInformativeText(f"""\
        Please enter a valid Meta Defender API key.
                        """)
                        # remove window title bar
                        msgBox.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)
                        msgBox.setWindowFlags(QtCore.Qt.FramelessWindowHint)
                        msgBox.exec_()
                    # if api key is not empty then scan the hash of the file
                    else:
                        M_header=({"apikey": MetaDefenderApiKey})
                        M_analysis = requests.get(meta_defender_api + readable_hash, headers=M_header)
                        M_analysis_json = M_analysis.json()
                        M_detections = M_analysis_json["scan_results"]["total_detected_avs"]
                        M_not_detections = M_analysis_json["scan_results"]["total_avs"]
                        half_M_not_detections = M_not_detections / 2
                        # show Meta Defender results
                        self.MetaDefenderWidget.show()
                        # if detections more than half of not detections print red
                        if M_detections > half_M_not_detections:
                            self.MetaDefenderDetectionsText.setStyleSheet("color: red")
                            self.MetaDefenderDetectionsText.setText(f"{str(M_detections)} | {str(M_not_detections)}")
                            self.IsFileVirusY_N.setStyleSheet("color: red")
                            if virus_found == False:
                                self.IsFileVirusY_N.setFont(QtGui.QFont("Arial", 10))
                                self.IsFileVirusY_N.setText("Probably a virus!")
                            else:
                                RESULTS.displayResults_VIRUS(self, file)
                        else:
                            self.MetaDefenderDetectionsText.setStyleSheet("color: green")
                            self.MetaDefenderDetectionsText.setText(f"{str(M_detections)} | {str(M_not_detections)}")
                            if virus_found == False:
                                self.IsFileVirusY_N.setStyleSheet("color: green")
                                self.IsFileVirusY_N.setFont(QtGui.QFont("Arial", 12))
                                self.IsFileVirusY_N.setText("Probably clean")
                            else:
                                RESULTS.displayResults_VIRUS(self, file)


                else:
                    # goto hidden results tab
                    self.Tabs.setCurrentIndex(2)
                    if virus_found == True:
                        RESULTS.displayResults_VIRUS(self, file)
                    else:
                        RESULTS.displayResults_CLEAN(self, file)

            # show error when Meta Defender api was not able to scan the file
            except Exception as e:
                # set results to ERROR
                self.MetaDefenderDetectionsText.setStyleSheet("color: red")
                self.MetaDefenderDetectionsText.setText("ERROR")

                # open log file
                LOG("-ERROR ;\n")
                LOG(str(e)+ "\n")
                    
                # show error box
                msgBox = QtWidgets.QMessageBox()
                msgBox.setIcon(QtWidgets.QMessageBox.Critical)
                msgBox.setText("Error")
                msgBox.setInformativeText(f"""\
        Cant scan file with Meta Defender.
                """)
                # remove window title bar
                msgBox.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)
                msgBox.setWindowFlags(QtCore.Qt.FramelessWindowHint)
                msgBox.exec_()

        # scan error
        except Exception as e:
            # change tab to home tab
            self.Tabs.setCurrentIndex(0)
            
            # open log file
            LOG("-ERROR ;\n") 
            LOG(str(e)+ "\n")

            # show error message
            msgBox = QtWidgets.QMessageBox()
            msgBox.setIcon(QtWidgets.QMessageBox.Critical)
            msgBox.setText("Error")
            msgBox.setInformativeText(f"""\
        No file selected or \nProgram has no permission to access file.\nOr error while scanning file.
            """)
            # remove window title bar
            msgBox.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)
            msgBox.setWindowFlags(QtCore.Qt.FramelessWindowHint)
            msgBox.exec_()

def browseFiles(MainWindow, self):

    # change tab to loading tab
    self.Tabs.setCurrentIndex(3)

    filepath_raw, filename_raw = os.path.split(str(QtWidgets.QFileDialog.getOpenFileName(MainWindow,
                                                                    "Select File",
                                                                    "YOUR-FILE-PATH")))
    
    filepath_raw = filepath_raw.replace("('", "")
    filename = filename_raw.replace("', 'All Files (*)')", "")

    # display file name
    self.FileName.setText("File Name: " + filename)
    # close thinker window
    
    # get full path to file
    filepath = (filepath_raw + "/" + filename)
    
    # display file path
    self.FilePath.setText("File Path:  " + filepath)
    
    threading.Thread(target=FILE_SCAN.scan(filepath, self, MainWindow)).start()

# UI (made with pyqt5)
class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(590, 300)
        MainWindow.setMinimumSize(QtCore.QSize(590, 300))
        MainWindow.setMaximumSize(QtCore.QSize(590, 300))
        # Window ico is a svg file so (i think) it will not make problems on Linux and Windows systems
        MainWindow.setWindowIcon(QtGui.QIcon(current_dir + "/res/ico/AntiVirus_ico.svg"))
        MainWindow.setStyleSheet("")

        #//////////////////////////////////////////////////////////////////////////////////////////////////////////////
        self.SideBar = QtWidgets.QLabel(MainWindow)
        self.SideBar.setGeometry(QtCore.QRect(-10, 45, 61, 271))
        self.SideBar.setStyleSheet("background-color: rgb(78, 86, 94);")
        self.SideBar.setText("")
        self.SideBar.setObjectName("SideBar")
        self.HomeTabButton = QtWidgets.QPushButton(MainWindow)
        self.HomeTabButton.setGeometry(QtCore.QRect(0, 50, 51, 31))
        self.HomeTabButton.setStyleSheet("background-color: qradialgradient(spread:pad, cx:0.5, cy:0.5, radius:0.5, fx:0.1468, fy:0.1468, stop:1 rgba(0, 0, 0, 0));\n"
"image: url(:/res/SideBar/home.svg);\n"
"")
        self.HomeTabButton.setText("")
        self.HomeTabButton.setFlat(True)
        self.HomeTabButton.setObjectName("HomeTabButton")
        self.SettingsTabButton = QtWidgets.QPushButton(MainWindow)
        self.SettingsTabButton.setGeometry(QtCore.QRect(0, 90, 51, 31))
        self.SettingsTabButton.setStyleSheet("background-color: qradialgradient(spread:pad, cx:0.5, cy:0.5, radius:0.5, fx:0.1468, fy:0.1468, stop:1 rgba(0, 0, 0, 0));\n"
"image: url(:/res/SideBar/settings.svg);")
        self.SettingsTabButton.setText("")
        self.SettingsTabButton.setFlat(True)
        self.SettingsTabButton.setObjectName("SettingsTabButton")
        self.Tabs = QtWidgets.QStackedWidget(MainWindow)
        self.Tabs.setGeometry(QtCore.QRect(50, 0, 591, 301))
        self.Tabs.setStyleSheet("")
        self.Tabs.setObjectName("Tabs")
        self.HomeTab = QtWidgets.QWidget()
        self.HomeTab.setObjectName("HomeTab")
        self.HomeTitle = QtWidgets.QLabel(self.HomeTab)
        self.HomeTitle.setGeometry(QtCore.QRect(0, 0, 551, 41))
        self.HomeTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
        self.HomeTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.HomeTitle.setObjectName("HomeTitle")
        self.SelectFileButton = QtWidgets.QPushButton(self.HomeTab)
        self.SelectFileButton.setGeometry(QtCore.QRect(5, 45, 121, 31))
        self.SelectFileButton.setFlat(False)
        self.SelectFileButton.setObjectName("SelectFileButton")
        self.ReportIssueButton = QtWidgets.QPushButton(self.HomeTab)
        self.ReportIssueButton.setGeometry(QtCore.QRect(5, 80, 121, 31))
        self.ReportIssueButton.setFlat(False)
        self.ReportIssueButton.setObjectName("ReportIssueButton")
        self.Tabs.addWidget(self.HomeTab)
        self.SettingsTab = QtWidgets.QWidget()
        self.SettingsTab.setObjectName("SettingsTab")
        self.SettingsTitle = QtWidgets.QLabel(self.SettingsTab)
        self.SettingsTitle.setGeometry(QtCore.QRect(0, 0, 551, 41))
        self.SettingsTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
        self.SettingsTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.SettingsTitle.setObjectName("SettingsTitle")
        self.UseVirusTotalApiCheckBox = QtWidgets.QCheckBox(self.SettingsTab)
        self.UseVirusTotalApiCheckBox.setGeometry(QtCore.QRect(5, 45, 531, 17))
        self.UseVirusTotalApiCheckBox.setStyleSheet("\n"
"QCheckBox::indicator:checked {\n"
"    image: url(:/res/Settings/check.svg);\n"
"}")
        self.UseVirusTotalApiCheckBox.setObjectName("UseVirusTotalApiCheckBox")
        self.VirusTotalApiKey = QtWidgets.QLineEdit(self.SettingsTab)
        self.VirusTotalApiKey.setGeometry(QtCore.QRect(5, 65, 391, 20))
        self.VirusTotalApiKey.setStyleSheet("")
        self.VirusTotalApiKey.setInputMask("")
        self.VirusTotalApiKey.setText("")
        self.VirusTotalApiKey.setMaxLength(32767)
        self.VirusTotalApiKey.setFrame(False)
        self.VirusTotalApiKey.setEchoMode(QtWidgets.QLineEdit.Password)
        self.VirusTotalApiKey.setAlignment(QtCore.Qt.AlignCenter)
        self.VirusTotalApiKey.setObjectName("VirusTotalApiKey")
        self.SaveSettingsButton = QtWidgets.QPushButton(self.SettingsTab)
        self.SaveSettingsButton.setGeometry(QtCore.QRect(415, 265, 121, 31))
        self.SaveSettingsButton.setFlat(False)
        self.SaveSettingsButton.setObjectName("SaveSettingsButton")
        self.UseMetaDefenderApiCheckBox = QtWidgets.QCheckBox(self.SettingsTab)
        self.UseMetaDefenderApiCheckBox.setGeometry(QtCore.QRect(5, 90, 541, 17))
        self.UseMetaDefenderApiCheckBox.setStyleSheet("\n"
"\n"
"QCheckBox::indicator:checked {\n"
"    image: url(:/res/Settings/check.svg);\n"
"}")
        self.UseMetaDefenderApiCheckBox.setObjectName("UseMetaDefenderApiCheckBox")
        self.MetaDefenderApiKey = QtWidgets.QLineEdit(self.SettingsTab)
        self.MetaDefenderApiKey.setGeometry(QtCore.QRect(5, 110, 391, 20))
        self.MetaDefenderApiKey.setStyleSheet("")
        self.MetaDefenderApiKey.setInputMask("")
        self.MetaDefenderApiKey.setText("")
        self.MetaDefenderApiKey.setMaxLength(32767)
        self.MetaDefenderApiKey.setFrame(False)
        self.MetaDefenderApiKey.setEchoMode(QtWidgets.QLineEdit.Password)
        self.MetaDefenderApiKey.setAlignment(QtCore.Qt.AlignCenter)
        self.MetaDefenderApiKey.setObjectName("MetaDefenderApiKey")
        self.LightModeButton = QtWidgets.QPushButton(self.SettingsTab)
        self.LightModeButton.setGeometry(QtCore.QRect(280, 265, 121, 31))
        self.LightModeButton.setFlat(False)
        self.LightModeButton.setObjectName("LightModeButton")
        self.Tabs.addWidget(self.SettingsTab)
        self.VirusScanResults_hidden = QtWidgets.QWidget()
        self.VirusScanResults_hidden.setObjectName("VirusScanResults_hidden")
        self.VirusResultsTitle = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.VirusResultsTitle.setGeometry(QtCore.QRect(0, 0, 551, 41))
        self.VirusResultsTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
        self.VirusResultsTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.VirusResultsTitle.setObjectName("VirusResultsTitle")
        self.FileName = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.FileName.setGeometry(QtCore.QRect(5, 45, 541, 31))
        self.FileName.setObjectName("FileName")
        self.FilePath = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.FilePath.setGeometry(QtCore.QRect(5, 75, 541, 31))
        self.FilePath.setObjectName("FilePath")
        self.FileHash = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.FileHash.setGeometry(QtCore.QRect(5, 110, 541, 31))
        self.FileHash.setObjectName("FileHash")
        self.label = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.label.setGeometry(QtCore.QRect(5, 160, 111, 31))
        self.label.setObjectName("label")
        self.IsFileVirusY_N = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.IsFileVirusY_N.setGeometry(QtCore.QRect(5, 190, 101, 31))
        self.IsFileVirusY_N.setStyleSheet("color: rgb(255, 0, 0);")
        self.IsFileVirusY_N.setAlignment(QtCore.Qt.AlignCenter)
        self.IsFileVirusY_N.setObjectName("IsFileVirusY_N")
        self.ReturnToHomeTabButton = QtWidgets.QPushButton(self.VirusScanResults_hidden)
        self.ReturnToHomeTabButton.setGeometry(QtCore.QRect(5, 265, 91, 31))
        self.ReturnToHomeTabButton.setDefault(False)
        self.ReturnToHomeTabButton.setFlat(False)
        self.ReturnToHomeTabButton.setObjectName("ReturnToHomeTabButton")
        self.DeleteFileButton = QtWidgets.QPushButton(self.VirusScanResults_hidden)
        self.DeleteFileButton.setGeometry(QtCore.QRect(100, 265, 111, 31))
        self.DeleteFileButton.setDefault(False)
        self.DeleteFileButton.setFlat(False)
        self.DeleteFileButton.setObjectName("DeleteFileButton")
        self.line = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.line.setGeometry(QtCore.QRect(0, 150, 540, 5))
        self.line.setStyleSheet("background-color: rgb(81, 89, 97);")
        self.line.setText("")
        self.line.setIndent(-1)
        self.line.setObjectName("line")
        self.VirusTotalWidget = QtWidgets.QWidget(self.VirusScanResults_hidden)
        self.VirusTotalWidget.setGeometry(QtCore.QRect(120, 160, 181, 71))
        self.VirusTotalWidget.setObjectName("VirusTotalWidget")
        self.label_3 = QtWidgets.QLabel(self.VirusTotalWidget)
        self.label_3.setGeometry(QtCore.QRect(10, 9, 161, 21))
        self.label_3.setAlignment(QtCore.Qt.AlignHCenter|QtCore.Qt.AlignTop)
        self.label_3.setObjectName("label_3")
        self.DetectionsText = QtWidgets.QLabel(self.VirusTotalWidget)
        self.DetectionsText.setGeometry(QtCore.QRect(10, 20, 161, 31))
        self.DetectionsText.setAlignment(QtCore.Qt.AlignCenter)
        self.DetectionsText.setObjectName("DetectionsText")
        self.label_5 = QtWidgets.QLabel(self.VirusTotalWidget)
        self.label_5.setGeometry(QtCore.QRect(10, 47, 161, 16))
        self.label_5.setAlignment(QtCore.Qt.AlignHCenter|QtCore.Qt.AlignTop)
        self.label_5.setObjectName("label_5")
        self.label_3.raise_()
        self.label_5.raise_()
        self.DetectionsText.raise_()
        self.MetaDefenderWidget = QtWidgets.QWidget(self.VirusScanResults_hidden)
        self.MetaDefenderWidget.setGeometry(QtCore.QRect(310, 160, 221, 71))
        self.MetaDefenderWidget.setObjectName("MetaDefenderWidget")
        self.label_4 = QtWidgets.QLabel(self.MetaDefenderWidget)
        self.label_4.setGeometry(QtCore.QRect(10, 9, 201, 21))
        self.label_4.setAlignment(QtCore.Qt.AlignHCenter|QtCore.Qt.AlignTop)
        self.label_4.setObjectName("label_4")
        self.MetaDefenderDetectionsText = QtWidgets.QLabel(self.MetaDefenderWidget)
        self.MetaDefenderDetectionsText.setGeometry(QtCore.QRect(10, 20, 201, 31))
        self.MetaDefenderDetectionsText.setAlignment(QtCore.Qt.AlignCenter)
        self.MetaDefenderDetectionsText.setObjectName("MetaDefenderDetectionsText")
        self.label_6 = QtWidgets.QLabel(self.MetaDefenderWidget)
        self.label_6.setGeometry(QtCore.QRect(10, 47, 201, 21))
        self.label_6.setAlignment(QtCore.Qt.AlignHCenter|QtCore.Qt.AlignTop)
        self.label_6.setObjectName("label_6")
        self.label_4.raise_()
        self.label_6.raise_()
        self.MetaDefenderDetectionsText.raise_()
        self.Tabs.addWidget(self.VirusScanResults_hidden)
        self.LoadingPage = QtWidgets.QWidget()
        self.LoadingPage.setObjectName("LoadingPage")
        self.LoadingPageTitle = QtWidgets.QLabel(self.LoadingPage)
        self.LoadingPageTitle.setGeometry(QtCore.QRect(-10, 0, 561, 41))
        self.LoadingPageTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
        self.LoadingPageTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.LoadingPageTitle.setObjectName("LoadingPageTitle")
        self.label_7 = QtWidgets.QLabel(self.LoadingPage)
        self.label_7.setGeometry(QtCore.QRect(0, 0, 541, 301))
        self.label_7.setAlignment(QtCore.Qt.AlignCenter)
        self.label_7.setObjectName("label_7")
        self.label_7.raise_()
        self.LoadingPageTitle.raise_()
        self.Tabs.addWidget(self.LoadingPage)
        self.version_display = QtWidgets.QLabel(MainWindow)
        self.version_display.setGeometry(QtCore.QRect(1, 284, 47, 20))
        self.version_display.setStyleSheet("background-color: qradialgradient(spread:pad, cx:0.5, cy:0.5, radius:0.5, fx:0.1468, fy:0.1468, stop:1 rgba(0, 0, 0, 0));")
        self.version_display.setObjectName("version_display")
        self.SideBar_2 = QtWidgets.QLabel(MainWindow)
        self.SideBar_2.setGeometry(QtCore.QRect(-10, -10, 71, 51))
        self.SideBar_2.setStyleSheet("background-color: rgb(81, 89, 97);")
        self.SideBar_2.setText("")
        self.SideBar_2.setObjectName("SideBar_2")
        self.CurrentTabHome = QtWidgets.QLabel(MainWindow)
        self.CurrentTabHome.setGeometry(QtCore.QRect(0, 50, 3, 31))
        self.CurrentTabHome.setStyleSheet("background-color: rgb(81, 89, 97);")
        self.CurrentTabHome.setText("")
        self.CurrentTabHome.setObjectName("CurrentTabHome")
        self.CurrentTabSettings = QtWidgets.QLabel(MainWindow)
        self.CurrentTabSettings.setGeometry(QtCore.QRect(0, 90, 3, 31))
        self.CurrentTabSettings.setStyleSheet("background-color: rgb(81, 89, 97);")
        self.CurrentTabSettings.setText("")
        self.CurrentTabSettings.setObjectName("CurrentTabSettings")
        #
        self.Tabs.setCurrentIndex(0)
        self.LANGUAGE.retranslateUi(self, MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        class SETTINGS():
            # read settings from ini file
            VirustotalScan = config.get('-settings-', 'VirusTotalScan')
            api_key = config.get('-settings-', 'VirusTotalApiKey')
            MetaDefenderScan = config.get('-settings-', 'MetaDefenderScan')
            MetaDefenderApiKey = config.get('-settings-', 'MetaDefenderApiKey')
            style = config.get('-settings-', 'Style')
        
            # apply settings
            if VirustotalScan == 'True':
                self.UseVirusTotalApiCheckBox.setChecked(True)
            else:
                self.UseVirusTotalApiCheckBox.setChecked(False)
            self.VirusTotalApiKey.setText(api_key)

            if MetaDefenderScan == 'True':
                self.UseMetaDefenderApiCheckBox.setChecked(True)
            else:
                self.UseMetaDefenderApiCheckBox.setChecked(False)
            self.MetaDefenderApiKey.setText(MetaDefenderApiKey)
        SETTINGS()

        from qt_material import apply_stylesheet
        extra = {
            # Density Scale
            'density_scale': '-1',
        }
        class STYLE():
            # apply stylesheet in settings
            if SETTINGS.style == "Dark":
                apply_stylesheet(MainWindow, theme=f'{current_dir}/res/themes/dark_red.xml', extra=extra)
                self.SideBar.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.SideBar_2.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.HomeTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.SettingsTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.VirusResultsTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.LoadingPageTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.LightModeButton.setText("Light Mode")
            if SETTINGS.style == "Light":
                apply_stylesheet(MainWindow, theme=f'{current_dir}/res/themes/light_pink.xml', extra=extra) 
                self.SideBar.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.SideBar_2.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.HomeTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.SettingsTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.VirusResultsTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.LoadingPageTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.LightModeButton.setText("Dark Mode")



            # if lightmode is enabled, apply light theme and change button text 
            def style_mode(self, MainWindow):
                if self.LightModeButton.text() == "Light Mode":
                    apply_stylesheet(MainWindow, theme=f'{current_dir}/res/themes/light_pink.xml', extra=extra)

                    self.CurrentTabHome.setStyleSheet("background-color: rgb(182, 182, 182);")
                    self.CurrentTabSettings.setStyleSheet("background-color: rgb(255, 0, 0);")
                    self.SideBar.setStyleSheet("background-color: rgb(182, 182, 182);")
                    self.SideBar_2.setStyleSheet("background-color: rgb(182, 182, 182);")
                    self.CurrentTabHome.setStyleSheet("background-color: rgb(182, 182, 182);")
                    self.CurrentTabSettings.setStyleSheet("background-color: rgb(231, 84, 128);")
                    # set title backgrounds
                    self.HomeTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                    self.SettingsTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                    self.VirusResultsTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                    self.LoadingPageTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                    self.LightModeButton.setText("Dark Mode")
                else:
                    apply_stylesheet(MainWindow, theme=f'{current_dir}/res/themes/dark_red.xml', extra=extra)

                    self.CurrentTabHome.setStyleSheet("background-color: rgb(81, 89, 97);")
                    self.CurrentTabSettings.setStyleSheet("background-color: rgb(255,192,203);")
                    self.SideBar.setStyleSheet("background-color: rgb(81, 89, 97);")
                    self.SideBar_2.setStyleSheet("background-color: rgb(81, 89, 97);")
                    self.CurrentTabHome.setStyleSheet("background-color: rgb(81, 89, 97);")
                    self.CurrentTabSettings.setStyleSheet("background-color: rgb(255, 0, 0);")
                    # set title backgrounds
                    self.HomeTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                    self.SettingsTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                    self.VirusResultsTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                    self.LoadingPageTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                    self.LightModeButton.setText("Light Mode")
        # apply default theme
        STYLE()

        class TABS():
            def change_tab_settings(self):
                self.Tabs.setCurrentIndex(0)
                self.HomeTabButton.setStyleSheet("image: url(:/res/SideBar/home.svg);\n")
                self.SettingsTabButton.setStyleSheet("image: url(:/res/SideBar/settings.svg);\n")
                if self.LightModeButton.text() == "Light Mode":
                    self.CurrentTabSettings.setStyleSheet("background-color: rgb(81, 89, 97);")
                    self.CurrentTabHome.setStyleSheet("background-color: rgb(255, 0, 0);")
                else:
                    # light mode
                    self.CurrentTabSettings.setStyleSheet("background-color: rgb(182, 182, 182);")
                    self.CurrentTabHome.setStyleSheet("background-color: rgb(231, 84, 128);")
                return

            def change_tab_home(self):
                self.Tabs.setCurrentIndex(1)
                self.SettingsTabButton.setStyleSheet("image: url(:/res/SideBar/settings.svg);\n")
                self.HomeTabButton.setStyleSheet("image: url(:/res/SideBar/home.svg);\n")
                if self.LightModeButton.text() == "Light Mode":
                    self.CurrentTabSettings.setStyleSheet("background-color: rgb(255, 0, 0);")
                    self.CurrentTabHome.setStyleSheet("background-color: rgb(81, 89, 97);")
                else:
                    # light mode
                    self.CurrentTabSettings.setStyleSheet("background-color: rgb(231, 84, 128);")
                    self.CurrentTabHome.setStyleSheet("background-color: rgb(182, 182, 182);")         
                return	

        class BUTTONS():
            # change tabs buttons
            self.HomeTabButton.clicked.connect(lambda: threading.Thread(target=TABS.change_tab_settings(self)).start())

            self.SettingsTabButton.clicked.connect(lambda: threading.Thread(target=TABS.change_tab_home(self)).start())

            # report issue button
            self.ReportIssueButton.clicked.connect(lambda: webbrowser.open_new(Report_issues))

            # open file dialog and scan file
            self.SelectFileButton.clicked.connect(lambda: threading.Thread(target=browseFiles(MainWindow, self)).start())

            # save settings button
            self.SaveSettingsButton.clicked.connect(lambda: threading.Thread(target=SaveSettings(self)).start())

            # style mode button
            self.LightModeButton.clicked.connect(lambda: threading.Thread(target=STYLE.style_mode(self, MainWindow)).start())

        # checking if the user has already downloaded the virus hashes else download them.
        threading.Thread(target=Get_Hashes(self, MainWindow)).start()

    class LANGUAGE():
        # set the text for all objects
        def retranslateUi(self, MainWindow):
            _translate = QtCore.QCoreApplication.translate
            self.HomeTitle.setText(_translate("MainWindow", "Home"))
            self.SelectFileButton.setText(_translate("MainWindow", "Scan File"))
            self.ReportIssueButton.setText(_translate("MainWindow", "report issue"))
            self.SettingsTitle.setText(_translate("MainWindow", "Settings"))
            self.UseVirusTotalApiCheckBox.setText(_translate("MainWindow", "Use Virus Total api (only files under 32MB) (files will be uploaded publicly)"))
            self.VirusTotalApiKey.setPlaceholderText(_translate("MainWindow", "Enter your Virus Total api Key here"))
            self.SaveSettingsButton.setText(_translate("MainWindow", "Safe config"))
            self.UseMetaDefenderApiCheckBox.setText(_translate("MainWindow", "Use Meta Defender api to check hash"))
            self.MetaDefenderApiKey.setPlaceholderText(_translate("MainWindow", "Enter your Meta Defender api Key here"))
            self.LightModeButton.setText(_translate("MainWindow", "Light Mode"))
            self.VirusResultsTitle.setText(_translate("MainWindow", "Virus Scan Results"))
            self.FileName.setText(_translate("MainWindow", "File Name: "))
            self.FilePath.setText(_translate("MainWindow", "File Path: "))
            self.FileHash.setText(_translate("MainWindow", "File Hash: "))
            self.label.setText(_translate("MainWindow", "Is This File A Virus?"))
            self.IsFileVirusY_N.setText(_translate("MainWindow", "YES"))
            self.ReturnToHomeTabButton.setText(_translate("MainWindow", "Return"))
            self.DeleteFileButton.setText(_translate("MainWindow", "Delete File"))
            self.label_3.setText(_translate("MainWindow", "Virus Total score"))
            self.DetectionsText.setText(_translate("MainWindow", "0"))
            self.label_5.setText(_translate("MainWindow", "Detections"))
            self.label_4.setText(_translate("MainWindow", "Meta Defender score"))
            self.MetaDefenderDetectionsText.setText(_translate("MainWindow", "0"))
            self.label_6.setText(_translate("MainWindow", "Detections"))
            self.LoadingPageTitle.setText(_translate("MainWindow", "..."))
            self.label_7.setText(_translate("MainWindow", "loading..."))
            #
            self.version_display.setText(_translate("MainWindow", f"v{VERSION}"))
            MainWindow.setWindowTitle(_translate("MainWindow", f"-AntiVirus- [v{VERSION}] [dev; {DEV}]"))
# import resources
import res.res_rc


if __name__ == "__main__":
    # Handle high resolution displays:
    if hasattr(QtCore.Qt, 'AA_EnableHighDpiScaling'):
        QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling, True)
    if hasattr(QtCore.Qt, 'AA_UseHighDpiPixmaps'):
        QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps, True)
    # create application
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QWidget()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())



