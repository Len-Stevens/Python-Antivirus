from PyQt5 import QtCore, QtGui, QtWidgets
from virustotal_python import Virustotal
from tkinter import filedialog
from tkinter import messagebox
from tkinter import *
import configparser
import webbrowser
import requests
import hashlib
import sys
import os

VERSION = "2.4"
DEV     = "cookie0_o, Len-Stevens"
# get current directory
current_dir = os.path.dirname(__file__)

# settings.ini file path
settings_file_path = current_dir + '/settings/settings.ini'


# define config
config = configparser.ConfigParser()
config.read(settings_file_path)

# UI (made with pyqt5)
class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(590, 300)
        MainWindow.setMinimumSize(QtCore.QSize(590, 300))
        MainWindow.setMaximumSize(QtCore.QSize(590, 300))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(":/res/ico/AntiVirus_ico.svg"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        MainWindow.setWindowIcon(icon)
        MainWindow.setStyleSheet("")
        self.SideBar = QtWidgets.QLabel(MainWindow)
        self.SideBar.setGeometry(QtCore.QRect(-10, 45, 61, 271))
        self.SideBar.setStyleSheet("background-color: rgb(81, 89, 97);")
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
        font = QtGui.QFont()
        font.setPointSize(10)
        self.Tabs.setFont(font)
        self.Tabs.setStyleSheet("")
        self.Tabs.setObjectName("Tabs")
        self.HomeTab = QtWidgets.QWidget()
        self.HomeTab.setObjectName("HomeTab")
        self.HomeTitle = QtWidgets.QLabel(self.HomeTab)
        self.HomeTitle.setGeometry(QtCore.QRect(0, 0, 551, 41))
        font = QtGui.QFont()
        font.setPointSize(23)
        self.HomeTitle.setFont(font)
        self.HomeTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.HomeTitle.setObjectName("HomeTitle")
        self.SelectFileButton = QtWidgets.QPushButton(self.HomeTab)
        self.SelectFileButton.setGeometry(QtCore.QRect(5, 45, 121, 31))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.SelectFileButton.setFont(font)
        self.SelectFileButton.setFlat(False)
        self.SelectFileButton.setObjectName("SelectFileButton")
        self.ReportIssueButton = QtWidgets.QPushButton(self.HomeTab)
        self.ReportIssueButton.setGeometry(QtCore.QRect(5, 85, 121, 31))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.ReportIssueButton.setFont(font)
        self.ReportIssueButton.setFlat(False)
        self.ReportIssueButton.setObjectName("ReportIssueButton")
        self.Tabs.addWidget(self.HomeTab)
        self.SettingsTab = QtWidgets.QWidget()
        self.SettingsTab.setObjectName("SettingsTab")
        self.SettingsTitle = QtWidgets.QLabel(self.SettingsTab)
        self.SettingsTitle.setGeometry(QtCore.QRect(0, 0, 551, 41))
        font = QtGui.QFont()
        font.setPointSize(23)
        self.SettingsTitle.setFont(font)
        self.SettingsTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.SettingsTitle.setObjectName("SettingsTitle")
        self.UseVirusTotalApiCheckBox = QtWidgets.QCheckBox(self.SettingsTab)
        self.UseVirusTotalApiCheckBox.setGeometry(QtCore.QRect(5, 45, 451, 17))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.UseVirusTotalApiCheckBox.setFont(font)
        self.UseVirusTotalApiCheckBox.setObjectName("UseVirusTotalApiCheckBox")
        self.VirusTotalApiKey = QtWidgets.QLineEdit(self.SettingsTab)
        self.VirusTotalApiKey.setGeometry(QtCore.QRect(5, 65, 391, 20))
        font = QtGui.QFont()
        font.setPointSize(7)
        self.VirusTotalApiKey.setFont(font)
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
        font = QtGui.QFont()
        font.setPointSize(10)
        self.SaveSettingsButton.setFont(font)
        self.SaveSettingsButton.setFlat(False)
        self.SaveSettingsButton.setObjectName("SaveSettingsButton")
        self.UseMetaDefenderApiCheckBox = QtWidgets.QCheckBox(self.SettingsTab)
        self.UseMetaDefenderApiCheckBox.setGeometry(QtCore.QRect(5, 90, 481, 17))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.UseMetaDefenderApiCheckBox.setFont(font)
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
        font = QtGui.QFont()
        font.setPointSize(10)
        self.LightModeButton.setFont(font)
        self.LightModeButton.setFlat(False)
        self.LightModeButton.setObjectName("LightModeButton")
        self.Tabs.addWidget(self.SettingsTab)
        self.VirusScanResults_hidden = QtWidgets.QWidget()
        self.VirusScanResults_hidden.setObjectName("VirusScanResults_hidden")
        self.VirusResultsTitle = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.VirusResultsTitle.setGeometry(QtCore.QRect(0, 0, 551, 41))
        font = QtGui.QFont()
        font.setPointSize(23)
        self.VirusResultsTitle.setFont(font)
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
        self.ReturnToHomeTabButton.setGeometry(QtCore.QRect(5, 265, 91, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.ReturnToHomeTabButton.setFont(font)
        self.ReturnToHomeTabButton.setDefault(False)
        self.ReturnToHomeTabButton.setFlat(False)
        self.ReturnToHomeTabButton.setObjectName("ReturnToHomeTabButton")
        self.DeleteFileButton = QtWidgets.QPushButton(self.VirusScanResults_hidden)
        self.DeleteFileButton.setGeometry(QtCore.QRect(100, 265, 111, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.DeleteFileButton.setFont(font)
        self.DeleteFileButton.setDefault(False)
        self.DeleteFileButton.setFlat(False)
        self.DeleteFileButton.setObjectName("DeleteFileButton")
        self.line = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.line.setGeometry(QtCore.QRect(0, 150, 540, 5))
        self.line.setStyleSheet("background-color: rgb(74, 74, 74);")
        self.line.setText("")
        self.line.setIndent(-1)
        self.line.setObjectName("line")
        self.VirusTotalWidget = QtWidgets.QWidget(self.VirusScanResults_hidden)
        self.VirusTotalWidget.setGeometry(QtCore.QRect(120, 160, 181, 71))
        self.VirusTotalWidget.setObjectName("VirusTotalWidget")
        self.label_3 = QtWidgets.QLabel(self.VirusTotalWidget)
        self.label_3.setGeometry(QtCore.QRect(10, 9, 161, 21))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_3.setFont(font)
        self.label_3.setAlignment(QtCore.Qt.AlignHCenter|QtCore.Qt.AlignTop)
        self.label_3.setObjectName("label_3")
        self.DetectionsText = QtWidgets.QLabel(self.VirusTotalWidget)
        self.DetectionsText.setGeometry(QtCore.QRect(10, 20, 161, 31))
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.DetectionsText.setFont(font)
        self.DetectionsText.setAlignment(QtCore.Qt.AlignCenter)
        self.DetectionsText.setObjectName("DetectionsText")
        self.label_5 = QtWidgets.QLabel(self.VirusTotalWidget)
        self.label_5.setGeometry(QtCore.QRect(10, 47, 161, 16))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_5.setFont(font)
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
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_4.setFont(font)
        self.label_4.setAlignment(QtCore.Qt.AlignHCenter|QtCore.Qt.AlignTop)
        self.label_4.setObjectName("label_4")
        self.MetaDefenderDetectionsText = QtWidgets.QLabel(self.MetaDefenderWidget)
        self.MetaDefenderDetectionsText.setGeometry(QtCore.QRect(10, 20, 201, 31))
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.MetaDefenderDetectionsText.setFont(font)
        self.MetaDefenderDetectionsText.setAlignment(QtCore.Qt.AlignCenter)
        self.MetaDefenderDetectionsText.setObjectName("MetaDefenderDetectionsText")
        self.label_6 = QtWidgets.QLabel(self.MetaDefenderWidget)
        self.label_6.setGeometry(QtCore.QRect(10, 47, 201, 21))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.label_6.setFont(font)
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
        font = QtGui.QFont()
        font.setPointSize(23)
        self.LoadingPageTitle.setFont(font)
        self.LoadingPageTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.LoadingPageTitle.setObjectName("LoadingPageTitle")
        self.label_7 = QtWidgets.QLabel(self.LoadingPage)
        self.label_7.setGeometry(QtCore.QRect(0, 0, 541, 301))
        font = QtGui.QFont()
        font.setPointSize(60)
        font.setBold(True)
        font.setWeight(75)
        self.label_7.setFont(font)
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
        self.SideBar_2.setText("")
        self.SideBar_2.setObjectName("SideBar_2")
        self.CurrentTabHome = QtWidgets.QLabel(MainWindow)
        self.CurrentTabHome.setGeometry(QtCore.QRect(0, 50, 3, 31))
        self.CurrentTabHome.setText("")
        self.CurrentTabHome.setObjectName("CurrentTabHome")
        self.CurrentTabSettings = QtWidgets.QLabel(MainWindow)
        self.CurrentTabSettings.setGeometry(QtCore.QRect(0, 90, 3, 31))
        self.CurrentTabSettings.setText("")
        self.CurrentTabSettings.setObjectName("CurrentTabSettings")
        #
        self.Tabs.setCurrentIndex(0)
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        # read settings from ini file
        VirustotalScan = config.get('-settings-', 'VirusTotalScan')
        api_key = config.get('-settings-', 'VirusTotalApiKey')
        MetaDefenderScan = config.get('-settings-', 'MetaDefenderScan')
        MetaDefenderApiKey = config.get('-settings-', 'MetaDefenderApiKey')
        style = config.get('-settings-', 'Style')


        # apply dark default theme
        from qt_material import apply_stylesheet
        extra = {
    
            # Density Scale
            'density_scale': '-2',
        }
        objects = [
            # buttons
            self.SelectFileButton,
            self.ReportIssueButton,
            self.LightModeButton,
            self.SaveSettingsButton,
            self.LightModeButton,
            self.ReturnToHomeTabButton,
            self.DeleteFileButton,
            # line edits
            self.MetaDefenderApiKey,
            self.VirusTotalApiKey,
            # check boxes
            self.UseVirusTotalApiCheckBox,
            self.UseMetaDefenderApiCheckBox,
            # background
            MainWindow,
            # labels
        ]

        # apply stylesheet in settings

        for object in objects:
            if style == "Dark":
                apply_stylesheet(object, theme=f'{current_dir}\\res\\themes\\dark_red.xml', extra=extra)
                self.SideBar.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.SideBar_2.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.HomeTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.SettingsTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.VirusResultsTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.LoadingPageTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.LightModeButton.setText("Light Mode")
            if style == "Light":
                apply_stylesheet(object, theme=f'{current_dir}\\res\\themes\\light_pink.xml', extra=extra)
                self.SideBar.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.SideBar_2.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.HomeTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.SettingsTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.VirusResultsTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.LoadingPageTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.LightModeButton.setText("Dark Mode")


        # if lightmode is enabled, apply light theme and change button text 
        def style_mode(self):
            if self.LightModeButton.text() == "Light Mode":
                for object in objects:
                    apply_stylesheet(object, theme=f'{current_dir}\\res\\themes\\light_pink.xml', extra=extra)
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
                for object in objects:
                    apply_stylesheet(object, theme=f'{current_dir}\\res\\themes\\dark_red.xml', extra=extra)
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


        # change tabs buttons
        self.HomeTabButton.clicked.connect(lambda: change_tab_settings(self))

        self.SettingsTabButton.clicked.connect(lambda: change_tab_home(self))

        # report issue button
        self.ReportIssueButton.clicked.connect(lambda: webbrowser.open_new(Report_issues))

        # open file dialog and scan file
        self.SelectFileButton.clicked.connect(lambda: browseFiles(MainWindow, self))

        # save settings button
        self.SaveSettingsButton.clicked.connect(lambda: SaveSettings(self))

        # style mode button
        self.LightModeButton.clicked.connect(lambda: style_mode(self))


    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", f"-AntiVirus- [v{VERSION}] [dev; {DEV}]"))
        self.HomeTitle.setText(_translate("MainWindow", "Home"))
        self.SelectFileButton.setText(_translate("MainWindow", "Scan File"))
        self.ReportIssueButton.setText(_translate("MainWindow", "report issue"))
        self.SettingsTitle.setText(_translate("MainWindow", "Settings"))
        self.UseVirusTotalApiCheckBox.setText(_translate("MainWindow", "Use Virus Total api (only files under 32MB) (files will be uploaded publicly)"))
        self.VirusTotalApiKey.setPlaceholderText(_translate("MainWindow", "Enter your Virus Total api Key here"))
        self.SaveSettingsButton.setText(_translate("MainWindow", "Safe config"))
        self.UseMetaDefenderApiCheckBox.setText(_translate("MainWindow", "Use Meta Defender api to check hash"))
        self.MetaDefenderApiKey.setPlaceholderText(_translate("MainWindow", "Enter your Meta Defender api Key here"))
        self.VirusResultsTitle.setText(_translate("MainWindow", "Virus Scan Results"))
        self.FileName.setText(_translate("MainWindow", "File Name: "))
        self.FilePath.setText(_translate("MainWindow", "File Path: "))
        self.FileHash.setText(_translate("MainWindow", "File Hash: "))
        self.label.setText(_translate("MainWindow", "Is This File A Virus?"))
        self.IsFileVirusY_N.setText(_translate("MainWindow", "YES"))
        self.ReturnToHomeTabButton.setText(_translate("MainWindow", "Return"))
        self.DeleteFileButton.setText(_translate("MainWindow", "Delete File"))
        self.label_3.setText(_translate("MainWindow", "Virus Total score"))
        self.DetectionsText.setText(_translate("MainWindow", "0 | 0"))
        self.label_5.setText(_translate("MainWindow", "Detections"))
        self.label_4.setText(_translate("MainWindow", "Meta Defender score"))
        self.MetaDefenderDetectionsText.setText(_translate("MainWindow", "0 | 0"))
        self.label_6.setText(_translate("MainWindow", "Detections"))
        self.LoadingPageTitle.setText(_translate("MainWindow", "..."))
        self.label_7.setText(_translate("MainWindow", "loading..."))
        self.version_display.setText(_translate("MainWindow", f"v{VERSION}"))