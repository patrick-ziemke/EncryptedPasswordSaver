# EncryptedPasswordSaver
This is a project for my Python class that uses the Ceasar Cypher to encrypt passwords
and store them in an external .pkl file using the pickle library. This script will load
this file and the user can look up their passwords, modify and delete entries in the file.

Python dependencies:
 - pickle
 - pandas
 - getpass
 
[+] EXAMPLE: pip install pandas

Note: This uses a very primitive form of encryption and is not meant for actually
storing passwords securely. This cipher can be brute forced in less than 30 seconds.
I am not responsible for stolen credentials using this software.
