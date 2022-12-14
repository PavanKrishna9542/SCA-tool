import re
import requests
import nvdlib
import time
import tkinter as tk
from tkinter import *
from tkinter import filedialog
import os
import json

repository=''
packages=[]
versions=[]

with open(r"sca_rules.txt","r") as f:
    version_patterns=[i.strip() for i in f.readlines()]

def find_dependencies():
    global repository,version_patterns,packages,versions
    total_dependencies=[]
    for parent,dirs,files in os.walk(repository):
        for file in files:
            if file.lower() == "package.json":
                f=open(parent+'/'+file)
                data=json.load(f)
                f.close()
                Dependencies=data['dependencies']
                total_dependencies.extend([dependency+' '+version.replace('^','')for dependency,version in Dependencies.items()])
            elif file.lower() == "package-lock.json":
                f=open(parent+'/'+file)
                data=json.load(f)
                f.close()
                Dependencies=data['dependencies']
                total_dependencies.extend([dependency+' '+Dependencies[dependency]["version"].replace('^','')for dependency in Dependencies.keys()])
            elif file.lower() == "gemfile.lock":
                with open(parent+'/'+file,"r",errors="ignore") as f:
                    for line in f.readlines():
                        matchObj = re.search( ".*\(.*\d\.[\d.]*.*\)", line.strip(),re.M|re.I)
                        if matchObj:
                            pat_1_depen=re.findall("(.*)(\([=(>=)(~>)(<=) ]*([\d.]+)[(alpha)(beta)]*[ ]*\))", line.strip(),re.M|re.I)

                            if pat_1_depen!=[]:
                                total_dependencies.append(pat_1_depen[0][0].strip()+' '+pat_1_depen[0][2].strip())
                                packages.append(pat_1_depen[0][0].strip())
                                versions.append(pat_1_depen[0][2].strip())
                                continue

                            pat_2_depen=re.findall("(.*)(\([ ]*~>[ ]*([\d.]+)[(alpha)(beta)]*[ ]*,[ ]*[(>=)(<=)]+[ ]*([\d.]+)[(alpha)(beta)]*[ ]*\))", line.strip(),re.M|re.I)
                            if pat_2_depen!=[]:
                                total_dependencies.append(pat_2_depen[0][0].strip()+' '+pat_2_depen[0][3].strip())
                                packages.append(pat_2_depen[0][0].strip())
                                versions.append(pat_2_depen[0][3].strip())
                                continue

                            pat_3_depen=re.findall("(.*)(\([ ]*>=[ ]*([\d.]+)[(alpha)(beta)]*[ ]*,[ ]*<[ ]*([\d.]+)[(alpha)(beta)]*[ ]*\))", line.strip(),re.M|re.I)
                            if pat_3_depen!=[]:
                                total_dependencies.append(pat_3_depen[0][0].strip()+' '+pat_3_depen[0][2].strip())
                                packages.append(pat_3_depen[0][0].strip())
                                versions.append(pat_3_depen[0][2].strip())
                                continue
    
                            #print(re.findall("([\d.]+)", line.strip(),re.M|re.I))
                            #print('--',matchObj)
                        
            else:
                with open(parent+'/'+file,"r",errors="ignore") as f:
                    for line in f.readlines():
                        for version_pattern in version_patterns:
                            matchObj = re.search( version_pattern, line.strip(),re.M|re.I)
                            if matchObj:
                                total_dependencies.append(matchObj.group())

    vulnerabilities={}                
    for pack in range(len(packages)):
        package = packages[pack]
        version = versions[pack]
        
        #print(total_dependencies[pack])
        url = "https://nvd.nist.gov//vuln/search/results?cpe_version=cpe:/:"+package+":"+package+":"+version

        headers = {
            'apiKey': 'edbfd5ca-2e1c-4eed-9e56-fe0093bd9389'
        }

        response = requests.request("GET", url, headers=headers)
        if set(re.findall("CVE-[\d]+-[\d]+", response.text,re.M|re.I))!=set():
            if package not in vulnerabilities:
                vulnerabilities[package]={}
            vulnerabilities[package][version]=set(re.findall("CVE-[\d]+-[\d]+", response.text,re.M|re.I))

    print('Vulnerabilities')
    print('-----------------------------------')
    for package in vulnerabilities:
        print(package,' :')
        for version in vulnerabilities[package]:
            print('    ',version,' --- ',','.join(vulnerabilities[package][version]))
            
    
        

def select_repository():
    global repository
    repository = filedialog.askdirectory()
    if repository!='':
        entry.delete(0,END)
        entry.insert(0,repository)
        
root = tk.Tk()
root.title('Software Composition Analysis Tool')
root.geometry('700x350')

# open button
browse_repository_button = Button(
    root,
    text='Browse Repository',
    command=select_repository
)

find_dependencies_button = Button(
    root,
    text='Run',
    command=find_dependencies
)

entry=Entry()
entry.place(x=30,y=55,width=400)
browse_repository_button.place(x=450,y=50)
find_dependencies_button.place(x=570,y=50)
root.mainloop()
