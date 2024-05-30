### IMPORTS ###
import virustotal_python
import configparser
import webbrowser
import threading
import requests
import hashlib
import os.path
import time
import sys
import os

# App Values like paths, etc.
from misc.values import Values

# Side functions like get_path, log, etc.
class Side_Functions():

    # change tab to defined tab
    def change_tab(self, tab, loading_msg):
        if tab == "home":
            self.Tabs.setCurrentIndex(0)
        elif tab == "settings":
            self.Tabs.setCurrentIndex(1)
        elif tab == "loading":
            self.Tabs.setCurrentIndex(3)
            self.label_2.setText(loading_msg)
        elif tab == "scan_results":
            self.Tabs.setCurrentIndex(2)

    # show user a message box with defined message
    def log_screen(self, message, title, msg_type):
        # create a message box
        msgBox = QMessageBox()
        # set the title and message of the message box
        msgBox.setText(message)
        msgBox.setWindowTitle(title)
        # set the message type
        if msg_type == "error":
            msgBox.setIcon(QMessageBox.Critical)
        elif msg_type == "info":
            msgBox.setIcon(QMessageBox.Information)
        # show the message box
        msgBox.exec_()

    # log defined message to "current_dir/log/*_log.txt"
    def log(self, message, log_type):
        if log_type == "error":
            log_path = Values.error_log_path
        else:
            log_path = Values.app_log_path
        # open the log file and write the message
        with open(log_path, "w") as log_file:
            log_file.write(message + " \n ")
        return

    # get user file to scan
    def browse_file(self):
        # change tab to loading tab
        Side_Functions.change_tab(self, "loading", "The file is being scanned \n [NOTE] Scanning with the VirusTotal API may not work/take longer than usual")
        # get file path
        filepath_raw, filename_raw = os.path.split(str(QtWidgets.QFileDialog.getOpenFileName(MainWindow,
                                                                        "Select File",
                                                                        "")))
        filepath_raw = filepath_raw.replace("('", "")
        filename = filename_raw.replace("', 'All Files (*)')", "")
        # get full path to file
        filepath = (filepath_raw + "/" + filename)
        # return file path and name
        return str(filepath), str(filename)

    # get the known Virus hashes from "https://virusshare.com/hashfiles/*.md5" 
    # and check if they are already installed # md5-Hashes_pack1.txt
    def get_hashes(MainWindow, self):
        try:
            # show loading screen
            Side_Functions.change_tab(self, "loading", "getting hashes from virusshare.com")
            # check if they are already installed
            if os.path.isfile(Values.MD5_HASHES_pack1):
                # change tab to home tab
                Side_Functions.change_tab(self, "home", "")
                return
            else:
                pass
            # define the url to get the hashes from
            pack_1_url = "https://virusshare.com/hashfiles/VirusShare_00000.md5"
            pack_2_url = "https://virusshare.com/hashfiles/VirusShare_00001.md5"
            pack_3_url = "https://virusshare.com/hashfiles/VirusShare_00002.md5"
            # download the hashes
            pack_1 = requests.get(pack_1_url)
            pack_2 = requests.get(pack_2_url)
            pack_3 = requests.get(pack_3_url)
            # save the hashes
            with open(Values.MD5_HASHES_pack1, "w") as f:
                f.write(pack_1.text)
            with open(Values.MD5_HASHES_pack2, "w") as f:
                f.write(pack_2.text)
            with open(Values.MD5_HASHES_pack3, "w") as f:
                f.write(pack_3.text)
            # close the file
            f.close()
            # change tab to home tab
            Side_Functions.change_tab(self, "home", "")
        # handle error
        except Exception as e:
            Side_Functions.log_screen(self, "Error: " + str(e), "Error (get Hashes)", "error")
            Side_Functions.log(self, "Error: " + str(e), "error (get Hashes)")
            Side_Functions.change_tab(self, "home", "")

    # set the file information to the virus results page
    def set_file_info(self, filename, filepath, readable_hash, virus_yes_no, VT_widget, MT_widget):
        # set Scan Results Page Information
        self.FileName.setText("File Name: " + filename)
        self.FilePath.setText("File Path: " + filepath)
        self.FileHash.setText("File Hash: " + readable_hash)

        if VT_widget == True:
            self.VirusTotalWidget.show()
        else:
            self.VirusTotalWidget.hide()

        if MT_widget == True:
            self.MetaDefenderWidget.show()
        else:
            self.MetaDefenderWidget.hide()

        if virus_yes_no == True:
            self.IsFileVirusY_N.setStyleSheet("color: red")
            self.IsFileVirusY_N.setText("Probably YES!")
        elif virus_yes_no == False:
            self.IsFileVirusY_N.setStyleSheet("color: green")
            self.IsFileVirusY_N.setText("Probably not.")   

    # delete scanned file
    def delete(self, file_path):
        e = False
        try:
            x = file_path
            os.remove(file_path)
            try:
                open(x, "rw")
                # if it can still find the file show error
                Side_Functions.log_screen(self, "Error: Error while deleting file", "Error (delete file)", "error")
                Side_Functions.log(self, "Error: Error while deleting file", "error (delete file)")
                e = True
            except:
                # if it cant find the file show success msg
                Side_Functions.log_screen(self, "Info: File deleted successfully", "Info (delete file)", "info")
                Side_Functions.log(self, "Info: File deleted successfully", "Info (delete file)")
        # handle error
        except Exception as e:
            if e == False:
                Side_Functions.log_screen(self, "Error: " + str(e), "Error (delete file)", "error")
                Side_Functions.log(self, "Error: " + str(e), "error (delete file)")    
            else:
                Side_Functions.log_screen(self, "Info: Looks like the file was already deleted", "Info (delete file)", "info")
                Side_Functions.log(self, "Info: Looks like the file was already deleted", "Info (delete file)")

    # add theme to ComboBox
    def setThemesComboBox(self):
        style = Settings.Read_Settings(MainWindow, self)[0]
        path, style = os.path.split(style)
        style = style.replace(".xml", "").replace("_", "-")
        # add current theme first to display it first
        self.ThemesComboBox.addItem(style)
        # add every theme to the comboBox in the theme folder
        for file in os.listdir(Values.theme_path):
            file = file.replace(".xml", "").replace("_", "-")
            if style == file:
                pass
            else:
                self.ThemesComboBox.addItem(file)
                
# side bar tab
class Tabs():
    def change_tab_home(self):
        try:
            # change tab to settings tab
            Side_Functions.change_tab(self, "home", "")
            # get theme
            style = Settings.Read_Settings(MainWindow, self)[0]
            style = style.replace(".xml", "").replace("_", " ")
            style_dl, color = style.split()
            #
            self.HomeTabButton.setStyleSheet("image: url(:/res/SideBar/home.svg);")
            self.SettingsTabButton.setStyleSheet("image: url(:/res/SideBar/settings.svg);")

            self.CurrentTabSettings.setStyleSheet(f"background-color: rgb(78, 86, 94);")
            self.CurrentTabHome.setStyleSheet(f"background-color: {color};")
        except:
            return

    def change_tab_settings(self):
        try:
            # change tab to home tab
            Side_Functions.change_tab(self, "settings", "")
            # get theme
            style = Settings.Read_Settings(MainWindow, self)[0]
            style = style.replace(".xml", "").replace("_", " ")
            style_dl, color = style.split()
            #
            self.SettingsTabButton.setStyleSheet("image: url(:/res/SideBar/settings.svg);")
            self.HomeTabButton.setStyleSheet("image: url(:/res/SideBar/home.svg);")

            self.CurrentTabSettings.setStyleSheet(f"background-color: {color};")
            self.CurrentTabHome.setStyleSheet(f"background-color: rgb(78, 86, 94);")
        except:
            return

# apply style
class Style():
    def style_mode(self, MainWindow, theme):
        try:
            # apply style
            apply_stylesheet(MainWindow, theme=Values.theme_path+theme, extra=Values.extra)

            # check if selected theme is dark or light
            style = theme.replace(".xml", "").replace("_", " ")
            style_dl, color = style.split()

            if style_dl == "light":
                self.SideBar.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.SideBar_2.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.CurrentTabHome.setStyleSheet(f"background-color: {color};")
                self.CurrentTabSettings.setStyleSheet(f"background-color: {color};")
                # set title backgrounds
                self.HomeTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.SettingsTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.VirusResultsTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.LoadingPageTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
            else:
                self.SideBar.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.SideBar_2.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.CurrentTabHome.setStyleSheet(f"background-color: {color};")
                self.CurrentTabSettings.setStyleSheet(f"background-color: {color};")
                # set title backgrounds
                self.HomeTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.SettingsTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.VirusResultsTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.LoadingPageTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
        except:
            return

# apply read and write user settings
class Settings():
    ### SAVE USER SETTINGS ###
    def Save_Settings(MainWindow, self):
        Side_Functions.change_tab(self, "loading", "saving settings")

        try:
            # init settings using ConfigParser
            config = configparser.ConfigParser()
            config.read(Values.app_settings_path)
            # read api keys
            VT_api_key = str(self.VirusTotalApiKey.text())
            MT_api_key = str(self.MetaDefenderApiKey.text())
            # check what is enabled
            use_VT_api = str(self.UseVirusTotalApiCheckBox.isChecked())
            use_MT_api = str(self.UseMetaDefenderApiCheckBox.isChecked())
            # theme
            theme = self.ThemesComboBox.currentText().replace("-", "_") + ".xml"
            # define the sections
            config['Config-Settings']['use_VT_api'] = str(use_VT_api)
            config['Config-Settings']['VT_api_key'] = str(VT_api_key)
            config["Config-Settings"]["use_MT_api"] = str(use_MT_api)
            config["Config-Settings"]["MT_api_key"] = str(MT_api_key)
            config["Settings"]["default_theme"]     = str(theme)
            # save the settings
            with open(Values.app_settings_path, 'w') as configfile: # save
                config.write(configfile)
            # apply style
            theme = Values.theme_path + self.ThemesComboBox.currentText().replace("-", "_") + ".xml"
            apply_stylesheet(MainWindow, theme=theme, extra=Values.extra)  
            # change tab to home tab
            Side_Functions.change_tab(self, "settings", "")
            # return
            return
        # handle error
        except Exception as e:
            Side_Functions.log_screen(self, "Error: " + str(e), "Error (Save Settings)", "error")
            Side_Functions.log(self, "Error: " + str(e), "error (Save Settings)")
            Side_Functions.change_tab(self, "settings", "")

    ### READ USER SETTINGS ###
    def Read_Settings(MainWindow, self):
        # init settings using ConfigParser
        config = configparser.ConfigParser()
        config.read(Values.app_settings_path)
        # get the values from the config file
        default_theme = config.get('Settings', 'default_theme')
        use_VT_api = config.get('Config-Settings', 'use_VT_api')
        use_MT_api = config.get('Config-Settings', 'use_MT_api')
        VT_api_key = config.get('Config-Settings', 'VT_api_key')
        MT_api_key = config.get('Config-Settings', 'MT_api_key')
        # return the values as strings
        return str(default_theme), str(use_VT_api), str(use_MT_api), str(VT_api_key), str(MT_api_key)

    ### APPLY USER SETTINGS ###
    def Apply_Settings(MainWindow, self):
        # check theme settings
        Style.style_mode(self, MainWindow, Settings.Read_Settings(MainWindow, self)[0])
        # check if Virus Total is enabled
        if Settings.Read_Settings(MainWindow, self)[1] == "True":
            self.UseVirusTotalApiCheckBox.setChecked(True)
        elif Settings.Read_Settings(MainWindow, self)[1] == "False":
            self.UseVirusTotalApiCheckBox.setChecked(False)
        # check if MetaDefender is enabled
        if Settings.Read_Settings(MainWindow, self)[2] == "True":
            self.UseMetaDefenderApiCheckBox.setChecked(True)
        elif Settings.Read_Settings(MainWindow, self)[2] == "False":
            self.UseMetaDefenderApiCheckBox.setChecked(False)
        # set the Virus Total API key
        self.VirusTotalApiKey.setText(Settings.Read_Settings(MainWindow, self)[3])
        # set the MetaDefender API key
        self.MetaDefenderApiKey.setText(Settings.Read_Settings(MainWindow, self)[4])
        # return
        return

### FILE SCAN ###
class File_Scan():
    def SCAN(MainWindow, self):
        try:

            # get the file to scan
            file_path, file_name = Side_Functions.browse_file(self)

            # get the file md5 hash
            with open(file_path,"rb") as target_file:
                bytes = target_file.read()
                # md5 hash of the file
                file_hash = hashlib.md5(bytes).hexdigest()
            # close the file
            target_file.close()

            # define temp values as false
            found_virus = False
            VT_widget   = False
            MT_widget   = False

            ### CHECK IF FILE IS A VIRUS ###

            # check if the file hash is in the pack 1 hash pack
            with open(Values.MD5_HASHES_pack1, "r") as f:
                for line in f:
                    # skip first 5 lines
                    if line.startswith("#"):
                        continue
                    # check if the file hash is in the pack 1 hash pack
                    if file_hash in line:
                        found_virus = True
                        break
            # close the file
            f.close()

            # check if the file hash is in the pack 2 hash pack
            if found_virus == False:
                with open(Values.MD5_HASHES_pack2, "r") as f:
                    for line in f:
                        # skip first 5 lines
                        if line.startswith("#"):
                            continue
                        # check if the file hash is in the pack 2 hash pack
                        if file_hash in line:
                            found_virus = True
                            break

            # check if the file hash is in the pack 3 hash pack
            if found_virus == False:
                with open(Values.MD5_HASHES_pack3, "r") as f:
                    for line in f:
                        # skip first 5 lines
                        if line.startswith("#"):
                            continue
                        # check if the file hash is in the pack 3 hash pack
                        if file_hash in line:
                            found_virus = True
                            break
        # handle error
        except Exception as e:
            Side_Functions.log_screen(self, "Error: " + str(e), "Error (scan file)", "error")
            Side_Functions.log(self, "Error: " + str(e), "error")
            Side_Functions.change_tab(self, "home", "") 
            return

        
        ### CHECK IF FILE IS A VIRUS USING THE SELECTED API(s) ###
        class API_CHECK():
            ## VIRUS-TOTAL API ##
            def VT_API(self, file_path, file_name):
                self.DetectionsText.setText("-")
                try:
                    # check if file is over 32mb 
                    if os.path.getsize(file_path) > 32000000:
                        # raise error
                        Side_Functions.log_screen(self, "Error: File is over 32MB", "Error (VT API)", "error")
                        # log error to log file
                        Side_Functions.log(self, "Error: File is over 32MB (Virus Total api)", "error")
                    else:
                        pass
                    # get the api key
                    VT_API_KEY = self.VirusTotalApiKey.text()
                    # check if the api key is empty
                    if VT_API_KEY == "":
                        # raise error
                        Side_Functions.log_screen(self, "Error: API Key is empty", "Error (VT API)", "error")
                        # log error to log file
                        Side_Functions.log(self, "Error: API Key is empty (Virus Total api)", "error")
                        return
                    else:
                        pass

                    ## UPLOAD FILE AND GET ID
                    # Create dictionary containing the file to send for multipart encoding upload
                    files = {"file": (os.path.basename(file_path), open(os.path.abspath(file_path), "rb"))}

                    with virustotal_python.Virustotal(VT_API_KEY) as vtotal:
                        resp = vtotal.request("files", files=files, method="POST")
                        id = str(resp.data["id"])

                    ## SEARCH FILE ID AND GET RESULTS
                    def scan(VT_API_KEY, id):
                        url = f"https://www.virustotal.com/api/v3/analyses/{id}"
                        headers = {
                            "accept": "application/json",
                            "X-Apikey": VT_API_KEY
                        }
                        analysis = requests.get(url, headers=headers)
                        analysis_json = analysis.json()
                        # get status
                        status = analysis_json["data"]["attributes"]["status"]
                        # return results
                        return analysis_json, status
                    # waiting for the scan to finish
                    while scan(VT_API_KEY, id)[1] == "queued":
                        time.sleep(2)
                    else:
                        pass
                    
                    analysis_json = scan(VT_API_KEY, id)[0]

                    detections = analysis_json["data"]["attributes"]["stats"]["malicious"]
                    not_detections = analysis_json["data"]["attributes"]["stats"]["undetected"]
                    # if detections more than half of not detections print red
                    if detections > not_detections:
                        self.DetectionsText.setStyleSheet("color: red")
                        self.DetectionsText.setText(f"{str(detections)} | {str(not_detections)}")
                    else:
                        self.DetectionsText.setStyleSheet("color: green")
                        self.DetectionsText.setText(f"{str(detections)} | {str(not_detections)}")
                # handle error
                except Exception as e:
                    Side_Functions.log_screen(self, "Error: " + str(e), "Error (VT API)", "error")
                    Side_Functions.log(self, "Error (VT API): " + str(e), "error")

            ## META DEFENDER API ##
            def MT_API(self, file_hash):
                self.MetaDefenderDetectionsText.setText("-")
                try:
                    # get the api key
                    MT_API_KEY = self.MetaDefenderApiKey.text()
                    if MT_API_KEY == "":
                        # raise error
                        Side_Functions.log_screen(self, "Error: API Key is empty", "Error (MT API)", "error")
                        # log error to log file
                        Side_Functions.log(self, "Error: API Key is empty (Meta Defender api)", "error")
                        return
                    else:
                        pass
                    # define headers for the api
                    header = {"apikey": MT_API_KEY}
                    # send the file hash to the api
                    analysis = requests.get("https://api.metadefender.com/v4/hash/" + file_hash, headers=header)#
                    # get the response as json
                    analysis_json = analysis.json()
                    # get detections and not detections
                    detections = analysis_json["scan_results"]["total_detected_avs"]
                    not_detections = analysis_json["scan_results"]["total_avs"]
                    # half not detections
                    half_not_detections = not_detections / 2
                    # if detections more than half of not detections print red
                    if detections > half_not_detections:
                        self.MetaDefenderDetectionsText.setStyleSheet("color: red")
                        self.MetaDefenderDetectionsText.setText(f"{str(detections)} | {str(not_detections)}")
                    else:
                        self.MetaDefenderDetectionsText.setStyleSheet("color: green")
                        self.MetaDefenderDetectionsText.setText(f"{str(detections)} | {str(not_detections)}")
                # handle error
                except Exception as e:
                    # show if hash was not found else show error
                    if analysis_json["error"]["code"] == 404003:
                        self.MetaDefenderDetectionsText.setStyleSheet("color: orange")
                        self.MetaDefenderDetectionsText.setText("Hash not found.")
                        self.label_6.setText("")
                    else:
                        Side_Functions.log_screen(self, "Error: " + str(e) + " / API RESPONSE: " + str(analysis_json), " Error (MT API)",  "error")
                        Side_Functions.log(self, "Error (MT API): " + str(e) + " / API RESPONSE: " + str(analysis_json), "error")

        # check what apis are selected
        if self.UseVirusTotalApiCheckBox.isChecked():
            try:
                API_CHECK.VT_API(self, file_path, file_name)
                # Show Virus Total Widget
                VT_widget = True
            except:
                pass

        if self.UseMetaDefenderApiCheckBox.isChecked():
            try:
                API_CHECK.MT_API(self, file_hash)
                # show the widget
                MT_widget = True
            except:
                pass

        # delete file button
        self.DeleteFileButton.clicked.connect(lambda: Side_Functions.delete(self, file_path))

        # check if there was any error while scanning with an api
        if self.DetectionsText.text() == "-":
            self.DetectionsText.setStyleSheet("color: red")
            self.DetectionsText.setText("ERROR")
            self.label_5.setText("")
        if self.MetaDefenderDetectionsText.text() == "-":
            self.MetaDefenderDetectionsText.setStyleSheet("color: red")
            self.MetaDefenderDetectionsText.setText("ERROR")
            self.label_6.setText("")

        # change tab to results tab
        Side_Functions.change_tab(self, "scan_results", "")
        try:
            # check if there was any error while scanning with an api
            # set Scan Results Page Information
            Side_Functions.set_file_info(self, file_name, file_path, file_hash, found_virus, VT_widget, MT_widget) 
        # handle error
        except:
            Side_Functions.change_tab(self, "home", "")
            pass



### UI IMPORTS ###
from PyQt5 import QtWidgets, QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QMessageBox
from qt_material import apply_stylesheet
import res.res_rc

### UI ###
class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(590, 300)
        # set the app icon
        MainWindow.setWindowIcon(QtGui.QIcon(Values.app_ico_path))
		# set max and min size of the window
        MainWindow.setMinimumSize(QtCore.QSize(590, 300))
        MainWindow.setMaximumSize(QtCore.QSize(590, 300))
        # set window title
        MainWindow.setWindowTitle(f"-AntiVirus- [v{Values.app_version}] [dev(s): {Values.app_developers()}]")
        
		## UI ELEMENTS ##
        self.SideBar = QtWidgets.QLabel(MainWindow)
        self.SideBar.setGeometry(QtCore.QRect(-10, 45, 61, 271))
        self.SideBar.setStyleSheet("background-color: rgb(78, 86, 94);")
        self.SideBar.setText("")
        self.SideBar.setObjectName("SideBar")
        self.HomeTabButton = QtWidgets.QPushButton(MainWindow)
        self.HomeTabButton.setGeometry(QtCore.QRect(0, 50, 51, 31))
        self.HomeTabButton.setStyleSheet("background-color: qradialgradient(spread:pad, cx:0.5, cy:0.5, radius:0.5, fx:0.1468, fy:0.1468, stop:1 rgba(0, 0, 0, 0));""image: url(:/res/SideBar/home.svg);")
        self.HomeTabButton.setText("")
        self.HomeTabButton.setFlat(True)
        self.HomeTabButton.setObjectName("HomeTabButton")
        self.SettingsTabButton = QtWidgets.QPushButton(MainWindow)
        self.SettingsTabButton.setGeometry(QtCore.QRect(0, 90, 51, 31))
        self.SettingsTabButton.setStyleSheet("background-color: qradialgradient(spread:pad, cx:0.5, cy:0.5, radius:0.5, fx:0.1468, fy:0.1468, stop:1 rgba(0, 0, 0, 0));""image: url(:/res/SideBar/settings.svg);")
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
        self.HomeTitle.setGeometry(QtCore.QRect(-10, 0, 551, 41))
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
        self.SettingsTitle.setGeometry(QtCore.QRect(-10, 0, 551, 41))
        self.SettingsTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
        self.SettingsTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.SettingsTitle.setObjectName("SettingsTitle")
        self.UseVirusTotalApiCheckBox = QtWidgets.QCheckBox(self.SettingsTab)
        self.UseVirusTotalApiCheckBox.setGeometry(QtCore.QRect(5, 45, 531, 17))
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
        self.label_8 = QtWidgets.QLabel(self.SettingsTab)
        self.label_8.setGeometry(QtCore.QRect(5, 135, 71, 16))
        self.label_8.setObjectName("label_8")
        self.ThemesComboBox = QtWidgets.QComboBox(self.SettingsTab)
        self.ThemesComboBox.setGeometry(QtCore.QRect(5, 152, 111, 22))
        self.ThemesComboBox.setObjectName("comboBox")
        """
        self.LightModeButton = QtWidgets.QPushButton(self.SettingsTab)
        self.LightModeButton.setGeometry(QtCore.QRect(280, 265, 121, 31))
        self.LightModeButton.setFlat(False)
        self.LightModeButton.setObjectName("LightModeButton")
        """
        self.Tabs.addWidget(self.SettingsTab)
        self.VirusScanResults_hidden = QtWidgets.QWidget()
        self.VirusScanResults_hidden.setObjectName("VirusScanResults_hidden")
        self.VirusResultsTitle = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.VirusResultsTitle.setGeometry(QtCore.QRect(-10, 0, 551, 41))
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
        self.IsFileVirusY_N.setGeometry(QtCore.QRect(5, 180, 101, 31))
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
        self.line.setStyleSheet("background-color: rgb(74, 74, 74);")
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
        self.LoadingPageTitle.setGeometry(QtCore.QRect(-20, 0, 561, 41))
        self.LoadingPageTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
        self.LoadingPageTitle.setText("")
        self.LoadingPageTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.LoadingPageTitle.setObjectName("LoadingPageTitle")
        self.label_7 = QtWidgets.QLabel(self.LoadingPage)
        self.label_7.setGeometry(QtCore.QRect(0, 0, 541, 181))
        self.label_7.setAlignment(QtCore.Qt.AlignCenter)
        self.label_7.setObjectName("label_7")
        self.label_2 = QtWidgets.QLabel(self.LoadingPage)
        self.label_2.setGeometry(QtCore.QRect(0, 159, 541, 61))
        self.label_2.setStyleSheet("color: rgb(0, 255, 0);")
        self.label_2.setAlignment(QtCore.Qt.AlignHCenter|QtCore.Qt.AlignTop)
        self.label_2.setObjectName("label_2")
        self.label_7.raise_()
        self.LoadingPageTitle.raise_()
        self.label_2.raise_()
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
        ##########
        # set default tab to home
        Tabs.change_tab_home(self)
        # set default language
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        ### SET LOG TEMPLATE ###
        log_template = f"""\
PY-Antivirus [v{Values.app_version}] 
##############################LOGS##############################\n"""
        Side_Functions.log(self, log_template, "error")
        Side_Functions.log(self, log_template, "app")
        ### BUTTONS ###

        ## HOME TAB ##
        self.SelectFileButton.clicked.connect(lambda: File_Scan.SCAN(MainWindow, self))
        self.ReportIssueButton.clicked.connect(lambda: webbrowser.open_new(Values.github_issues_link))

        ## VIRUS RESULTS PAGE ##
        self.ReturnToHomeTabButton.clicked.connect(lambda: Side_Functions.change_tab(self, "home", ""))

        ## SIDE BAR ##
        self.HomeTabButton.clicked.connect(lambda: Tabs.change_tab_home(self))
        self.SettingsTabButton.clicked.connect(lambda: Tabs.change_tab_settings(self))

        ## SETTINGS PAGE ##
        self.SaveSettingsButton.clicked.connect(lambda: Settings.Save_Settings(MainWindow, self))
        
        ### add themes to the combo box ###
        Side_Functions.setThemesComboBox(self)

        ### CHECK AND INSTALL KNOWN VIRUS HASHES ###
        threading.Thread(target=Side_Functions.get_hashes, args=(MainWindow, self)).start()

        ### GET SETTINGS ###
        Settings.Apply_Settings(MainWindow, self)

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
        self.label_8.setText(_translate("MainWindow", "Theme"))
        self.VirusResultsTitle.setText(_translate("MainWindow", "Virus Scan Results"))
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
        self.LoadingPageTitle.setText(_translate("MainWindow", ""))
        self.label_7.setText(_translate("MainWindow", "loading..."))
        self.version_display.setText(_translate("MainWindow", f"v{Values.app_version}"))


### CONSTRUCT THE UI ###
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