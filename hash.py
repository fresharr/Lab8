#Matt Arrison and Andrew Shashin
#SY402 Lab 08

import os, time, hashlib, csv
from time import time, ctime
t = time()

unhashable = {'dev', 'proc', 'run', 'sys', 'tmp'}

def main():
    if os.path.isfile("/tmp/SecureFileLog.csv"):
        print("Basline hash file detected. Hashing file system for comparison...")
        compareHash()
        quit()
    else:
        print("Basline hash file not detected. Hashing file system to create file...")
        createFile()
        quit()

#root: current path that is walked through
#dirs: files in root of type directory
#files: files in root (not dirs) of type other than directory
def createFile():
    outputFile = open("/tmp/SecureFileLog.csv", "w")

    for root, dirs, files in os.walk("/", topdown=True):

        if root == "/":
            for item in unhashable:
                if item in dirs:
                    dirs.remove(item)

        if root == "/var":
            dirs.remove("lib")
            dirs.remove("run")
            dirs.remove("ossec")
            dirs.remove("spool")
        elif root == "/usr/src/linux-headers-4.15.0-140/scripts/dtc/include-prefixes":
            files.remove("nios2")
            files.remove("powerpc")
        elif root == "/usr/src/linux-headers-4.15.0-112/scripts/dtc/include-prefixes":
            files.remove("nios2")
            files.remove("powerpc")
        elif root == "/usr":
            dirs.remove("share")

        for name in files:
            Files = (os.path.join(root,name))
            hasher = hashlib.sha256()
            with open(Files, 'rb') as readable:
                reader = readable.read()
                hasher.update(reader)

            file = str(os.path.join(root,name))
            hash = str(hasher.hexdigest())
            totalString = file + ',' + hash + ',' + ctime(t) + ','
            outputFile.write(totalString) #write data to saved file
    outputFile.close()
    print("File created!")
def compareHash():
    with open("/tmp/SecureFileLog.csv") as f:
        oldHashlist = f.read().strip(",").split(",")
    stringlen = "1" * len(oldHashlist[::-3])
    oldHashlist[::-3] = stringlen #set all date indexes to "1"
    for item in oldHashlist:
        if item == "1":
            #leaves oldHashlist as only names and hashes
            oldHashlist.remove(item) #deletes all "1" from list
    newList = []
    totalMods = []
    totalNewFiles = []
    totalMissingFiles = []
    # print(oldHashlist)

    for root, dirs, files in os.walk("/", topdown=True):

        if root == "/":
            for item in unhashable:
                if item in dirs:
                    dirs.remove(item)

        if root == "/var":
            dirs.remove("lib")
            dirs.remove("run")
            dirs.remove("ossec")
            dirs.remove("spool")
        elif root == "/usr/src/linux-headers-4.15.0-140/scripts/dtc/include-prefixes":
            files.remove("nios2")
            files.remove("powerpc")
        elif root == "/usr/src/linux-headers-4.15.0-112/scripts/dtc/include-prefixes":
            files.remove("nios2")
            files.remove("powerpc")
        elif root == "/usr":
            dirs.remove("share")

        for name in files:
            Files = (os.path.join(root,name))
            hasher = hashlib.sha256()
            with open(Files, 'rb') as readable:
                reader = readable.read()
                hasher.update(reader)

            file = str(os.path.join(root,name))
            hash = str(hasher.hexdigest())
            newList.append(file)
            newList.append(hash)

    #compare lists
    index = 0
    end1 = len(oldHashlist)
    end2 = len(newList)

    # print(oldHashlist)
    # print(newList)

    #set end parameter
    if end1 > end2:
        end = end1
        compareList = oldHashlist
        dif = end1 - end2
        newList += dif * ["1"] #make list length equal
    elif end2 > end1:
        end = end2
        compareList = newList
        dif = end2 - end1
        oldHashlist += dif * ["1"] #make list length equal
    elif end1 == end2:
        end = end1
        compareList = oldHashlist

    #compare lists
    for item in compareList:
        while index <= end-2:
            if oldHashlist[index] in newList: #file still exists
                name = newList.index(oldHashlist[index])
                newhash = newList[name+1]

                if oldHashlist[index+1] != newhash: #hash different
                    # print("old: " + str(oldHashlist))
                    oldHashlist[index+1] = newhash #set new hash
                    # print("new: " + str(oldHashlist))
                    totalMods.append(oldHashlist[index] + ": " + oldHashlist[index+1])

            if oldHashlist[index] not in newList:
                if oldHashlist[index] != "1":
                    totalMissingFiles.append(oldHashlist[index]) #missing the file

            if newList[index] not in oldHashlist:
                if newList[index] != "1":
                    totalNewFiles.append(newList[index]) #new file detected

            index += 2

    # print(oldHashlist)
    # print(newList)

    #print updates
    print("\n********UPDATES***********\n")
    print("Files modified:")
    if totalMods == []:
        print("None\n")
    else:
        for item in totalMods:
            print(item)
        print("\n")

    print("Files removed:")
    if totalMissingFiles == []:
        print("None\n")
    else:
        for item in totalMissingFiles:
            print(item)
        print("\n")

    print("Files added:")
    if totalNewFiles == []:
        print("None\n")
    else:
        for item in totalNewFiles:
            print(item)
        print("\n")

    #rewrite list for SecureFileLog
    i = 2
    while i <= len(oldHashlist):
        oldHashlist.insert(i, ctime(t))
        i += 3

    #write to log
    with open("/tmp/SecureFileLog.csv", "w") as f:
        write = csv.writer(f)
        write.writerow(oldHashlist) #update file

    f.close()

main()
#
#         #check changes in saved file
#         if search_array(hash in x for x in oldHashlist)==False:
#             filechanges.append(str(os.path.join(root,name)))
#
#         hlist= hash not in oldHashlist
#         flist=hash not in filechanges
#         if flist==True:
#             if hlist==True:
#                 print(str("New hash detected: " + hash))
#
# #print output of file chages
# if filechanges == []:
#     print("There were no file changes")
# else:
#     print("These were modified files"+ '\n' + str(filechanges))
#
# outputFile.close()
