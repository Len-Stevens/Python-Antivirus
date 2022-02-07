import hashlib
import os
from functools import partial
import json
from tkinter import *
from tkinter import filedialog


def scan_sha256(file):
      virus_found = False

      with open(file,"rb") as f:
            bytes = f.read()
            readable_hash = hashlib.sha256(bytes).hexdigest();

            print("The SHA256 hash of this file is: " + readable_hash)

            with open("SHA256.txt",'r') as f:
                lines = [line.rstrip() for line in f]
                for line in lines:
                      if str(readable_hash) == str(line.split(";")[0]):
                            virus_found = True

                f.close()

      if not virus_found:
            print("File is safe!")
            label_status.configure(text="Status: File is safe!", width = 100, height = 4,  
                            fg = "green")
      else:
            print("Virus detected! File quarantined")
            label_status.configure(text="Status: Virus detected! File Deleted!", width = 100, height = 4,  
                            fg = "red")
            os.remove(file)

def scan_md5(file):
      virus_found = False

      with open(file,"rb") as f:
            bytes = f.read()
            readable_hash = hashlib.md5(bytes).hexdigest();

            print("The MD5 hash of this file is: " + readable_hash)

            with open("MD5 Virus Hashes.txt",'r') as f:
                lines = [line.rstrip() for line in f]
                for line in lines:
                      if str(readable_hash) == str(line.split(";")[0]):
                            virus_found = True

                f.close()

      if not virus_found:
            print("File is safe!")
            label_status.configure(text="Status: File is safe!", width = 100, height = 4,  
                            fg = "green")

            scan_sha256(file)
      else:
            print("Virus detected! File quarentined")
            label_status.configure(text="Status: Virus detected! File Deleted!", width = 100, height = 4,  
                            fg = "red")
            os.remove(file)



def scan(file):
      virus_found = False

      with open(file,"rb") as f:
            bytes = f.read()
            readable_hash = hashlib.sha1(bytes).hexdigest();

            print("The SHA1 hash of this file is: " + readable_hash)
      
                      
            with open('SHA1 HASHES.json', 'r') as f:
                dataset = json.loads(f.read())

                for index, item in enumerate(dataset["data"]):
                      if str(item['hash']) == str(readable_hash):
                          virus_found = True

                f.close()

      if not virus_found:
            print("File is safe!")
            label_status.configure(text="Status: File is safe!", width = 100, height = 4,  
                            fg = "green")

            scan_md5(file)
      else:
            print("Virus detected! File quarentined")
            label_status.configure(text="Status: Virus detected! File Deleted!", width = 100, height = 4,  
                            fg = "red")
            os.remove(file)
   
def browseFiles():
    filename = filedialog.askopenfilename(initialdir = "/", 
                                          title = "Select a File", 
                                          filetypes = (("Text files", 
                                                        "*.*"), 
                                                       ("all files", 
                                                        "*.*"))) 
      
    opened_file.configure(text="File Opened: "+filename)

    scan(filename)
       
                                                                                                   
window = Tk() 

window.title('Antivirus') 

window.geometry("500x500")

window.config(background = "white") 
    
label_file_explorer = Label(window,  
                            text = "Antivirus", 
                            width = 100, height = 4,  
                            fg = "blue"
                            ,bg = "white")

label_file_explorer.config(font=("Courier", 15))

label_status = Label(window,  
                            text = "Status: ", 
                            width = 100, height = 4,  
                            fg = "blue",
                     bg = "white")

label_status.config(font=("Courier", 10))

opened_file = Label(window,  
                            text = "File Opened: ", 
                            width = 100, height = 4,  
                            fg = "blue",
                    bg = "white")

opened_file.config(font=("Courier", 10))
       
button_explore = Button(window,  
                        text = "Browse Files", 
                        command = browseFiles)
   
label_file_explorer.grid(column = 1, row = 1)
label_file_explorer.place(x=-350, y=0)

opened_file.grid(column = 1, row = 1)
opened_file.place(x=-150, y=250)

label_status.grid(column = 1, row = 1)
label_status.place(x=-150, y=300)
   
button_explore.grid(column = 1, row = 2)
button_explore.place(x=205, y=400)

window.mainloop()
