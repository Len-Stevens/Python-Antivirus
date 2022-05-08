# imports
from PyQt5 import QtCore, QtGui, QtWidgets
from tkinter import filedialog
from tkinter import messagebox
from tkinter import *
import webbrowser
import hashlib
import json
import sys
import os
from tkinter import *

# get current directory
current_dir = os.path.dirname(__file__)

# get files with Virus hashes inside
SHA256_HASHES = (current_dir + '\\hard_signatures\\SHA256-Hashes.txt')
MD5_HASHES    = (current_dir + '\\hard_signatures\\MD5-Hashes.txt')
SHA1_HASHES   = (current_dir + '\\hard_signatures\\SHA1-HASHES.json')

# define Stuff
VERSION = "1.0"
DEV     = "cookie0_o, Len-Stevens"

# url´s
Report_issues = "https://github.com/cookie0o/Python-Antivirus-beta-ui/issues/new"
Submit_sample = "https://github.com/cookie0o/Python-Antivirus-beta-ui/discussions/1"

# remove file
def removeFile(file):
    # define thinker root again AGAIN since it was destroyed 3 times now xD
    root = Tk()
    # set ico
    root.iconbitmap(current_dir + '\\res\\ico\\AntiVirus_ico.ico')
    # set size
    root.geometry("0x0")
    
    try:
        os.remove(file)
        response=messagebox.showinfo("Info", "File successfully deleted.")
        # close thinker window when ok is clicked
        if response:
            root.destroy()
    except:
        response=messagebox.showinfo("Error", "File could not be deleted.")
        # close thinker window when ok is clicked
        if response:
            root.destroy()


# display results
def displayResults_VIRUS(self, file):
    self.IsFileVirusY_N.setStyleSheet("color: red")
    self.IsFileVirusY_N.setText("YES!")

    # delete file button
    self.DeleteFileButton.clicked.connect(lambda: removeFile(file))

    # return button
    self.ReturnToHomeTabButton.clicked.connect(lambda: self.Tabs.setCurrentIndex(0))


def displayResults_CLEAN(self, file):
    self.IsFileVirusY_N.setStyleSheet("color: green")
    self.IsFileVirusY_N.setText("NO!")

    # delete file button
    self.DeleteFileButton.clicked.connect(lambda: removeFile(file))

    # return button
    self.ReturnToHomeTabButton.clicked.connect(lambda: self.Tabs.setCurrentIndex(0))


def scan(file, self, MainWindow):
    try:
        
        # goto hidden results tab
        self.Tabs.setCurrentIndex(2)

        # default virus found to false
        virus_found = False


        # open file and get hash
        with open(file,"rb") as f:
            bytes = f.read()
            readable_hash = hashlib.sha256(bytes).hexdigest();

        # display hash
        self.FileHash.setText("File Hash:  " + readable_hash)

        # check if from the selected is = to a hash in the virus hash list

        # SHA256 HASHES check
        with open(SHA1_HASHES,'r') as f:
            lines = [line.rstrip() for line in f]
            for line in lines:
                if str(readable_hash) == str(line.split(";")[0]):
                    virus_found = True
        f.close()



        # check if virus is found else pass and check next hash
        if virus_found == True:
            displayResults_VIRUS(self, file)
            return
        else:
            pass



        # MD5 HASHES check
        with open(MD5_HASHES,'r') as f:
            lines = [line.rstrip() for line in f]
            for line in lines:
                if str(readable_hash) == str(line.split(";")[0]):
                    virus_found = True
        f.close()



        # check if virus is found else pass and check next hash
        if virus_found == True:
            displayResults_VIRUS(self, file)
            return
        else:
            pass



        # SHA1 HASHES check
        with open(SHA1_HASHES, 'r') as f:
            dataset = json.loads(f.read())

            for index, item in enumerate(dataset["data"]):
                if str(item['hash']) == str(readable_hash):
                    virus_found = True

            f.close()

        # display results of scan
        if virus_found == True:
            displayResults_VIRUS(self, file)
        else:
            displayResults_CLEAN(self, file)

    except:
        # change tab to home tab
        self.Tabs.setCurrentIndex(0)

        # define thinker root again since it was destroyed
        root = Tk()
        # set ico
        root.iconbitmap(current_dir + '\\res\\ico\\AntiVirus_ico.ico')
        # set size
        root.geometry("0x0")

        # show error message
        response=messagebox.showinfo("Error", "No file selected or \nProgram has no permission to access file.")
        # close thinker window when ok is clicked
        if response:
            root.destroy()



# BROWSE FILE
def browseFiles(MainWindow, self):
    # define thinker root
    root = Tk()
    # set ico
    root.iconbitmap(current_dir + '\\res\\ico\\AntiVirus_ico.ico')
    # set size
    root.geometry("0x0")

    filepath_raw, filename = os.path.split(filedialog.askopenfilename(initialdir = "/", 
                                          title = "Select a File", 
                                          filetypes = (("Text files", 
                                                        "*.*"), 
                                                       ("all files", 
                                                        "*.*"))))
    # display file name
    self.FileName.setText("File Name: " + filename)
    # close thinker window
    root.destroy()
    
    # get full path to file
    filepath = (filepath_raw + "/" + filename)
    
    # display file path
    self.FilePath.setText("File Path:  " + filepath)
    
    scan(filepath, self, MainWindow)


# UI (made with pyqt5)
class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        # Handle high resolution displays:
        if hasattr(QtCore.Qt, 'AA_EnableHighDpiScaling'):
            QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling, True)
        if hasattr(QtCore.Qt, 'AA_UseHighDpiPixmaps'):
            QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps, True)
        
        # create Window
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(590, 300)
        MainWindow.setMinimumSize(QtCore.QSize(590, 300))
        MainWindow.setMaximumSize(QtCore.QSize(590, 300))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(":/res/ico/AntiVirus_ico.svg"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        MainWindow.setWindowIcon(icon)
        MainWindow.setStyleSheet("background-color: rgb(115, 115, 115);")
        self.SideBar = QtWidgets.QLabel(MainWindow)
        self.SideBar.setGeometry(QtCore.QRect(0, 0, 51, 301))
        self.SideBar.setStyleSheet("background-color: rgb(74, 74, 74);")
        self.SideBar.setText("")
        self.SideBar.setObjectName("SideBar")
        self.HomeTabButton = QtWidgets.QPushButton(MainWindow)
        self.HomeTabButton.setGeometry(QtCore.QRect(0, 50, 51, 31))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.HomeTabButton.setFont(font)
        self.HomeTabButton.setStyleSheet("background-color: qradialgradient(spread:pad, cx:0.5, cy:0.5, radius:0.5, fx:0.1468, fy:0.1468, stop:1 rgba(0, 0, 0, 0));\n"
"image: url(:/res/SideBar/home.svg);\n"
"")
        self.HomeTabButton.setText("")
        self.HomeTabButton.setFlat(True)
        self.HomeTabButton.setObjectName("HomeTabButton")
        self.SettingsTabButton = QtWidgets.QPushButton(MainWindow)
        self.SettingsTabButton.setGeometry(QtCore.QRect(0, 90, 51, 31))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.SettingsTabButton.setFont(font)
        self.SettingsTabButton.setStyleSheet("background-color: qradialgradient(spread:pad, cx:0.5, cy:0.5, radius:0.5, fx:0.1468, fy:0.1468, stop:1 rgba(0, 0, 0, 0));\n"
"image: url(:/res/SideBar/settings.svg);")
        self.SettingsTabButton.setText("")
        self.SettingsTabButton.setFlat(True)
        self.SettingsTabButton.setObjectName("SettingsTabButton")
        self.Tabs = QtWidgets.QStackedWidget(MainWindow)
        self.Tabs.setGeometry(QtCore.QRect(50, 0, 591, 301))
        self.Tabs.setObjectName("Tabs")
        self.HomeTab = QtWidgets.QWidget()
        self.HomeTab.setObjectName("HomeTab")
        self.HomeTitle = QtWidgets.QLabel(self.HomeTab)
        self.HomeTitle.setGeometry(QtCore.QRect(0, 0, 541, 41))
        font = QtGui.QFont()
        font.setPointSize(23)
        self.HomeTitle.setFont(font)
        self.HomeTitle.setStyleSheet("background-color: rgb(74, 74, 74);")
        self.HomeTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.HomeTitle.setObjectName("HomeTitle")
        self.SelectFileButton = QtWidgets.QPushButton(self.HomeTab)
        self.SelectFileButton.setGeometry(QtCore.QRect(5, 45, 121, 31))
        font = QtGui.QFont()
        font.setPointSize(20)
        self.SelectFileButton.setFont(font)
        self.SelectFileButton.setFlat(True)
        self.SelectFileButton.setObjectName("SelectFileButton")
        self.Background_3 = QtWidgets.QLabel(self.HomeTab)
        self.Background_3.setGeometry(QtCore.QRect(5, 45, 121, 31))
        self.Background_3.setStyleSheet("background-color: rgb(74, 74, 74);")
        self.Background_3.setText("")
        self.Background_3.setObjectName("Background_3")
        self.ReportIssueButton = QtWidgets.QPushButton(self.HomeTab)
        self.ReportIssueButton.setGeometry(QtCore.QRect(5, 85, 121, 31))
        font = QtGui.QFont()
        font.setPointSize(16)
        self.ReportIssueButton.setFont(font)
        self.ReportIssueButton.setFlat(True)
        self.ReportIssueButton.setObjectName("ReportIssueButton")
        self.Background_4 = QtWidgets.QLabel(self.HomeTab)
        self.Background_4.setGeometry(QtCore.QRect(5, 85, 121, 31))
        self.Background_4.setStyleSheet("background-color: rgb(74, 74, 74);")
        self.Background_4.setText("")
        self.Background_4.setObjectName("Background_4")
        self.HomeTitle.raise_()
        self.Background_3.raise_()
        self.SelectFileButton.raise_()
        self.Background_4.raise_()
        self.ReportIssueButton.raise_()
        self.Tabs.addWidget(self.HomeTab)
        self.SettingsTab = QtWidgets.QWidget()
        self.SettingsTab.setObjectName("SettingsTab")
        self.SettingsTitle = QtWidgets.QLabel(self.SettingsTab)
        self.SettingsTitle.setGeometry(QtCore.QRect(0, 0, 541, 41))
        font = QtGui.QFont()
        font.setPointSize(23)
        self.SettingsTitle.setFont(font)
        self.SettingsTitle.setStyleSheet("background-color: rgb(74, 74, 74);")
        self.SettingsTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.SettingsTitle.setObjectName("SettingsTitle")
        self.textBrowser = QtWidgets.QTextBrowser(self.SettingsTab)
        self.textBrowser.setGeometry(QtCore.QRect(0, 277, 261, 31))
        self.textBrowser.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.textBrowser.setOpenExternalLinks(True)
        self.textBrowser.setObjectName("textBrowser")
        self.Tabs.addWidget(self.SettingsTab)
        self.VirusScanResults_hidden = QtWidgets.QWidget()
        self.VirusScanResults_hidden.setObjectName("VirusScanResults_hidden")
        self.VirusResultsTitle = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.VirusResultsTitle.setGeometry(QtCore.QRect(0, 0, 541, 41))
        font = QtGui.QFont()
        font.setPointSize(23)
        self.VirusResultsTitle.setFont(font)
        self.VirusResultsTitle.setStyleSheet("background-color: rgb(74, 74, 74);")
        self.VirusResultsTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.VirusResultsTitle.setObjectName("VirusResultsTitle")
        self.FileName = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.FileName.setGeometry(QtCore.QRect(5, 45, 541, 31))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.FileName.setFont(font)
        self.FileName.setObjectName("FileName")
        self.FilePath = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.FilePath.setGeometry(QtCore.QRect(5, 75, 541, 31))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.FilePath.setFont(font)
        self.FilePath.setObjectName("FilePath")
        self.FileHash = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.FileHash.setGeometry(QtCore.QRect(5, 110, 541, 31))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.FileHash.setFont(font)
        self.FileHash.setObjectName("FileHash")
        self.label = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.label.setGeometry(QtCore.QRect(5, 160, 111, 31))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.IsFileVirusY_N = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.IsFileVirusY_N.setGeometry(QtCore.QRect(5, 190, 101, 31))
        font = QtGui.QFont()
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.IsFileVirusY_N.setFont(font)
        self.IsFileVirusY_N.setStyleSheet("color: rgb(255, 0, 0);")
        self.IsFileVirusY_N.setAlignment(QtCore.Qt.AlignCenter)
        self.IsFileVirusY_N.setObjectName("IsFileVirusY_N")
        self.ReturnToHomeTabButton = QtWidgets.QPushButton(self.VirusScanResults_hidden)
        self.ReturnToHomeTabButton.setGeometry(QtCore.QRect(5, 264, 91, 31))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.ReturnToHomeTabButton.setFont(font)
        self.ReturnToHomeTabButton.setDefault(False)
        self.ReturnToHomeTabButton.setFlat(True)
        self.ReturnToHomeTabButton.setObjectName("ReturnToHomeTabButton")
        self.DeleteFileButton = QtWidgets.QPushButton(self.VirusScanResults_hidden)
        self.DeleteFileButton.setGeometry(QtCore.QRect(100, 265, 91, 31))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.DeleteFileButton.setFont(font)
        self.DeleteFileButton.setDefault(False)
        self.DeleteFileButton.setFlat(True)
        self.DeleteFileButton.setObjectName("DeleteFileButton")
        self.ButtonBackground = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.ButtonBackground.setGeometry(QtCore.QRect(5, 264, 91, 31))
        self.ButtonBackground.setStyleSheet("background-color: rgb(74, 74, 74);")
        self.ButtonBackground.setText("")
        self.ButtonBackground.setObjectName("ButtonBackground")
        self.ButtonBackground_2 = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.ButtonBackground_2.setGeometry(QtCore.QRect(100, 264, 91, 31))
        self.ButtonBackground_2.setStyleSheet("background-color: rgb(74, 74, 74);")
        self.ButtonBackground_2.setText("")
        self.ButtonBackground_2.setObjectName("ButtonBackground_2")
        self.line = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.line.setGeometry(QtCore.QRect(0, 150, 540, 5))
        self.line.setStyleSheet("background-color: rgb(74, 74, 74);")
        self.line.setText("")
        self.line.setIndent(-1)
        self.line.setObjectName("line")
        self.VirusResultsTitle.raise_()
        self.FileName.raise_()
        self.FilePath.raise_()
        self.FileHash.raise_()
        self.label.raise_()
        self.IsFileVirusY_N.raise_()
        self.ButtonBackground.raise_()
        self.ReturnToHomeTabButton.raise_()
        self.ButtonBackground_2.raise_()
        self.DeleteFileButton.raise_()
        self.line.raise_()
        self.Tabs.addWidget(self.VirusScanResults_hidden)
        self.version_display = QtWidgets.QLabel(MainWindow)
        self.version_display.setGeometry(QtCore.QRect(1, 284, 47, 20))
        self.version_display.setStyleSheet("background-color: qradialgradient(spread:pad, cx:0.5, cy:0.5, radius:0.5, fx:0.1468, fy:0.1468, stop:1 rgba(0, 0, 0, 0));")
        self.version_display.setObjectName("version_display")
        self.label_2 = QtWidgets.QLabel(MainWindow)
        self.label_2.setGeometry(QtCore.QRect(-10, 41, 61, 4))
        self.label_2.setText("")
        self.label_2.setObjectName("label_2")

        self.Tabs.setCurrentIndex(0)
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        # change tabs buttons
        self.HomeTabButton.clicked.connect(lambda: self.Tabs.setCurrentIndex(0))
        self.SettingsTabButton.clicked.connect(lambda: self.Tabs.setCurrentIndex(1))

        # report issue button
        self.ReportIssueButton.clicked.connect(lambda: webbrowser.open_new(Report_issues))

        # open file dialog and scan file
        self.SelectFileButton.clicked.connect(lambda: browseFiles(MainWindow, self))


    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", f"-AntiVirus- [v{VERSION}] [dev; {DEV}]"))
        self.HomeTitle.setText(_translate("MainWindow", "Home Tab"))
        self.SelectFileButton.setText(_translate("MainWindow", "Scan File"))
        self.ReportIssueButton.setText(_translate("MainWindow", "report issue"))
        self.SettingsTitle.setText(_translate("MainWindow", "Settings Tab"))
        self.textBrowser.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; font-weight:400; font-style:normal;\">\n"
f"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><a href=\"{Submit_sample}\"><span style=\" font-size:10pt; font-weight:600; text-decoration: underline; color:#000000;\">Report Virus Hashes</span></a><a href=\"https://github.com/cookie0o/Python-Antivirus-beta-ui/discussions/1\"><span style=\" font-size:10pt; text-decoration: underline; color:#0000ff;\"> here!</span></a></p></body></html>"))
        self.VirusResultsTitle.setText(_translate("MainWindow", "Virus Scan Results"))
        self.FilePath.setText(_translate("MainWindow", "File Path: "))
        self.FileName.setText(_translate("MainWindow", "File Name: "))
        self.FileHash.setText(_translate("MainWindow", "File Hash: "))
        self.label.setText(_translate("MainWindow", "Is This File A Virus?"))
        self.IsFileVirusY_N.setText(_translate("MainWindow", "YES"))
        self.ReturnToHomeTabButton.setText(_translate("MainWindow", "Return"))
        self.DeleteFileButton.setText(_translate("MainWindow", "Delete File"))
        self.version_display.setText(_translate("MainWindow", f"v{VERSION}"))
# import resources
import res.res_rc


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QWidget()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
