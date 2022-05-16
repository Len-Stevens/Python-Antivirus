# imports
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
from scripts.window import Ui_MainWindow

# get current directory
current_dir = os.path.dirname(__file__)

# settings.ini file path
settings_file_path = current_dir + '/settings/settings.ini'


# define config
config = configparser.ConfigParser()
config.read(settings_file_path)

# get files with Virus hashes inside
SHA256_HASHES_pack1 = (current_dir + '\\hard_signatures\\SHA256-Hashes_pack1.txt')
SHA256_HASHES_pack2 = (current_dir + '\\hard_signatures\\SHA256-Hashes_pack2.txt')
SHA256_HASHES_pack3 = (current_dir + '\\hard_signatures\\SHA256-Hashes_pack3.txt')

# define Stuff
VERSION = "2.4"
DEV     = "cookie0_o, Len-Stevens"

# url´s
Report_issues = "https://github.com/Len-Stevens/Python-Antivirus/issues/new"
Submit_sample = "https://github.com/Len-Stevens/Python-Antivirus/discussions/8"
virus_total_api = "https://www.virustotal.com/api/v3/files/report"
meta_defender_api = "https://api.metadefender.com/v4/hash/" # + hash

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
        # define thinker root again AGAIN since it was destroyed 3 times now xD
        root = Tk()
        # set ico
        root.iconbitmap(current_dir + '\\res\\ico\\AntiVirus_ico.ico')
        # set size
        root.geometry("0x0")
        
        try:
            os.remove(file)
        except:
            response=messagebox.showinfo("Error", "File could not be deleted.")
            # close thinker window when ok is clicked
            if response:
                root.destroy()
        finally:
            response=messagebox.showinfo("Info", "File successfully deleted.")
            # close thinker window when ok is clicked
            if response:
                root.destroy()


# display results
def displayResults_VIRUS(self, file):
    self.Tabs.setCurrentIndex(2)
    # check if virus total check if on and file is under 32mb
    if self.UseVirusTotalApiCheckBox.isChecked() and os.path.getsize(file) < 32000000:
        self.VirusTotalWidget.show()
    else:
        # hide Virus total results since it is not needed
        self.VirusTotalWidget.hide()
    # check if meta defender check if on and file is under 120mb
    if self.UseMetaDefenderApiCheckBox.isChecked() and os.path.getsize(file) < 120000000:
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
    # check if meta defender check if on and file is under 120mb
    if self.UseMetaDefenderApiCheckBox.isChecked() and os.path.getsize(file) < 120000000:
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


def scan(file, self, MainWindow):
    try:

    
        # default virus found to false
        virus_found = False


        # open file and get hash
        with open(file,"rb") as f:
            bytes = f.read()
            readable_hash = hashlib.sha256(bytes).hexdigest();

        # display hash
        self.FileHash.setText("File Hash:  " + readable_hash)

        # check if from the selected is = to a hash in the virus hash list

        # SHA256 HASHES check + pack 1
        with open(SHA256_HASHES_pack1,'r') as f:
            lines = [line.rstrip() for line in f]
            for line in lines:
                if str(readable_hash) == str(line.split(";")[0]):
                    virus_found = True
                    f.close()
        f.close()
        # check if virus is found else pass
        if virus_found == True:
            pass
        else:
            pass
        if virus_found == False:
            # SHA256 HASHES check + pack 2
            with open(SHA256_HASHES_pack2,'r') as f:
                lines = [line.rstrip() for line in f]
                for line in lines:
                    if str(readable_hash) == str(line.split(";")[0]):
                        virus_found = True
                        f.close()
            f.close()
        else:
            pass
        if virus_found == False:
            # SHA256 HASHES check + pack 3
            with open(SHA256_HASHES_pack3,'r') as f:
                lines = [line.rstrip() for line in f]
                for line in lines:
                    if str(readable_hash) == str(line.split(";")[0]):
                        virus_found = True
                        f.close()
            f.close()
        else:
            pass

        try:
            # check if Virus total api is checked and file is under 32mb then scan the file with Virus total
            if self.UseVirusTotalApiCheckBox.isChecked() and os.path.getsize(file) < 32000000:
                # get api key
                api_key = self.VirusTotalApiKey.text()
                # check if api key is empty if yes then show error
                if api_key == "":
                    # define thinker root again (this is getting old) since it was destroyed
                    root = Tk()
                    # set ico
                    root.iconbitmap(current_dir + '\\res\\ico\\AntiVirus_ico.ico')
                    # set size
                    root.geometry("0x0")
                    # display error
                    response=messagebox.showinfo("Error", "Please enter a valid Virus Total API key.")
                    # close thinker window when ok is clicked
                    if response:
                        root.destroy()
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
                            displayResults_VIRUS(self, file)
                    else:
                        self.DetectionsText.setStyleSheet("color: green")
                        self.DetectionsText.setText(f"{str(detections)}")
                        if virus_found == False:
                            self.IsFileVirusY_N.setStyleSheet("color: green")
                            self.IsFileVirusY_N.setFont(QtGui.QFont("Arial", 12))
                            self.IsFileVirusY_N.setText("Probably clean")
                        else:
                            displayResults_VIRUS(self, file)
            else:
                pass
        except:
            # define thinker root again (this is getting very old) since it was destroyed
            root = Tk()
            # set ico
            root.iconbitmap(current_dir + '\\res\\ico\\AntiVirus_ico.ico')
            # set size
            root.geometry("0x0")
            # display error
            response=messagebox.showinfo("Error", "Cant scan file with Virus Total.")
            # hide Virus Total results
            self.VirusTotalWidget.hide()
            # close thinker window when ok is clicked
            if response:
                root.destroy()
                pass

        try:
            # Meta Defender hash check
            if self.UseMetaDefenderApiCheckBox.isChecked():
                # get api key
                MetaDefenderApiKey = self.MetaDefenderApiKey.text()
                # check if api key is empty if yes then show error
                if MetaDefenderApiKey == "":
                    # define thinker root again (this is getting very old) since it was destroyed
                    root = Tk()
                    # set ico
                    root.iconbitmap(current_dir + '\\res\\ico\\AntiVirus_ico.ico')
                    # set size
                    root.geometry("0x0")
                    # display error
                    response=messagebox.showinfo("Error", "Please enter a valid Meta Defender API key.")
                    # close thinker window when ok is clicked
                    if response:
                        root.destroy()
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
                            displayResults_VIRUS(self, file)
                    else:
                        self.MetaDefenderDetectionsText.setStyleSheet("color: green")
                        self.MetaDefenderDetectionsText.setText(f"{str(M_detections)} | {str(M_not_detections)}")
                        if virus_found == False:
                            self.IsFileVirusY_N.setStyleSheet("color: green")
                            self.IsFileVirusY_N.setFont(QtGui.QFont("Arial", 12))
                            self.IsFileVirusY_N.setText("Probably clean")
                        else:
                            displayResults_VIRUS(self, file)

            else:
                # goto hidden results tab
                self.Tabs.setCurrentIndex(2)
                if virus_found == True:
                    displayResults_VIRUS(self, file)
                else:
                    displayResults_CLEAN(self, file)
        except:
            # define thinker root again (this is getting very old) since it was destroyed
            root = Tk()
            # set ico
            root.iconbitmap(current_dir + '\\res\\ico\\AntiVirus_ico.ico')
            # set size
            root.geometry("0x0")
            # display error
            response=messagebox.showinfo("Error", "Cant scan file with Meta Defender.")
            # hide meta defender results
            self.MetaDefenderWidget.hide()
            # close thinker window when ok is clicked
            if response:
                root.destroy()
                pass
        
        finally:
            # goto hidden results tab
            self.Tabs.setCurrentIndex(2)

            # delete file button
            self.DeleteFileButton.clicked.connect(lambda: removeFile(file))
            # return button
            self.ReturnToHomeTabButton.clicked.connect(lambda: self.Tabs.setCurrentIndex(0))


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

    finally:
        return



# BROWSE FILE
def browseFiles(MainWindow, self):

    # change tab to loading tab
    self.Tabs.setCurrentIndex(3)

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
