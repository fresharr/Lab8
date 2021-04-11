***Works best if line 26 and line 75 is changed to "." directory, but still works for the whole system***

Our hash.py file stores its data by opening SecureFileLog.csv in the /tmp directory.
It then hashes every file, starting at the directory defined on line 26, and stores the
information in a csv file in the order "filename", "hash", "time. 

Once the file is created, hash.py opens the file, deletes every third item in the list 
(to only contain the name of the file and the hash), walks through the entire system
hashing every file, to then created a new list of the current files and hashes.

hash.py compares these two lists to determine what is manipulated, what is missing, and
what is added, then outputs the old file with the new information.