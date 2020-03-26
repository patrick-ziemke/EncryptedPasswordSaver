import pickle
import sys
import pandas as pd
import getpass

entries = {}
password_file_name = "encryptedPasswords.pickle"
encryption_key = 16

menu_text = """
What would you like to do:
1. Open password file
2. Lookup a password
3. Add a password
4. Edit entry
5. Delete entry
6. Save password file
7. Print the encrypted password list (for testing)
8. Quit program
Please enter a number (1-8)"""

def checkComplexity(unencryptedPass):
    """
    Checks if a password is complex enough. Must include an uppercase and lowercase
    letter, and also must be longer than 8 characters.

    :param unencryptedPass (string) Password to be checked
    :return complex (boolean) True if password is complex enough
    """
    upperCase = 0
    lowerCase = 0
    symbols = 0
    complex = False                                       
    for character in unencryptedPass:                          
        if ord(character) >= 65 and ord(character) <= 90:   #checks character ASCII code
            upperCase += 1
        elif ord(character) >= 97 and ord(character) <= 122:
            lowerCase += 1
        else:
            symbols += 1
    if (upperCase == 0) or (lowerCase == 0) or (symbols == 0):   #checks if password is missing anything
        print("Your password is not secure enough.\nYou must include an uppercase and lowercase letter along with a symbol.")
        return complex
    elif len(unencryptedPass) < 8:                               #checks if password is less than 8 characters
        print("Your password is not secure enough.\nYour password must be at least 8 characters long.")
        return complex
    else:
        complex = True    #returns true if both conditions are met
        return complex

###########   ENCRYPTION FUNCTION   ###########
def encryption(mode, message, key):
    """Returns an encrypted message using a caesar cypher
    :param mode ('encrypt'/'decrypt')
    :param unencrypted_message (string)
    :param key (int) The offset to be used for the caesar cypher
    :return (string) The encrypted message
    """
    charLst = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    if mode == "encrypt":   #------Encryption Mode------
        encryptedMessage = ""
        for character in message:   # repeats for every character in message
            if character.isalpha(): 
                idx = charLst.index(character)  
                for i in range(0, key):             #repeats 'key' number of times
                    if idx < (len(charLst) - 1):    #increase index until it reaches the end of the list
                        idx += 1
                    else:                           #once it reaches the end of the list
                        idx = 0                     #go to beginning of list
                encryptedMessage += charLst[idx]
            else:
                encryptedMessage += character
        return encryptedMessage     #returns encrypted password

    else:                   #------Decryption Mode-------
        decryptedMessage = ""
        for character in message:
            if character.isalpha():
                idx = charLst.index(character)
                for i in range(0, key):
                    if idx < 1: #when index gets to beginning of list
                        idx = len(charLst) - 1  #move to end of list
                    else:
                        idx -= 1                # cipher travels in opposite direction
                decryptedMessage += charLst[idx]
            else:
                decryptedMessage += character
        return decryptedMessage     #returns decrypted password

def load_entries():
    """
    Loads entries dictionary from pickle file
    :return entries (dict)
    """
    entries = {}    #initialize entries dictionary
    with (open(password_file_name, 'rb')) as openfile:  #opens password file
        try:
            entries = pickle.load(openfile)     
            openfile.close()
        except EOFError:    
            print("File is empty...")
            pass
    return entries  #return entries dictionary

def print_entries():
    entries = load_entries()
    dataFrame = pd.DataFrame(entries)   #creates pandas dataframe
    print(dataFrame)                    #prints formatted pandas dataframe

def save_password_file():
    """Saves a password file.  The file will be created if it doesn't exist.
    """
    entries = load_entries()    
    writeFile = open(password_file_name, 'wb')
    pickle.dump(entries, writeFile)     
    writeFile.close()

def add_entry():
    """
    Adds entry to entries dictionary. The entry is in the following format:
    { website : {username : "$USERNAME", password : "$PASSWORD", url : "$URL" } }
    Uses getpass so password is hidden as you type into the console for added security.
    """
    print("What website is this password for?")
    website = input()
    print("What is the URL?")
    url = input()
    print("What is the username?")
    username = input()
    secure = False
    while not secure:   #repeat until security requirements are met
        print("What is the password?")
        unencrypted_password = getpass.getpass()    #password doesn't appear in plaintext in console
        if checkComplexity(unencrypted_password):   
            print("Password is secure")             
            secure = True     
        else:
            pass

    entries = load_entries()
    entries.update( {website : {'Username:' : username,
                             'Password:' : encryption('encrypt', unencrypted_password, encryption_key),
                             'URL:' : url}} )   #updating dictionary (NOTE: password is being encrypted here)
    writeFile = open(password_file_name, 'wb')
    pickle.dump(entries, writeFile)     
    writeFile.close()

def lookup_password():
    """Lookup the password for a given website
    :return: Returns the decrypted password.  Returns None if no entry is found
    """
    print("Which website do you want to lookup the password for?")
    website = input()
    entries = load_entries()
    if website in entries:  
        print("Entry found!")
        password = entries[website]['Password:']    #accessing nested dictionary
        decryptedPass = encryption('decrypt', password, encryption_key) #decrypting password
        print("Your password is:  %s" % decryptedPass)
    else:  
        print("\x1b[1;31mEntry not found!\x1b[1;37m")
        pass

def edit():
    """
    Edits the username, password, or URL of an entry within the entries dictionary
    """
    print("Which website do you want to edit?")
    website = input()
    entries = load_entries()
    if website in entries:
        print("Entry found!")
        print("Would you like to change the: ")
        print("""
    1. Username
    2. Password
    3. Website URL
        """)
        choice = int(input("Please select an option (1-3): "))
        if choice == 1:
            newUsername = input("Please enter a new username for %s: " % website)
            entries[website]['Username:'] = newUsername #ursername key in website dictionary
            print("Username updated successfully.")
        if choice == 2:
            print("Please enter a new password for %s" % website)
            newPass = getpass.getpass()
            encryptedPass = encryption("encrypt", newPass, encryption_key)
            entries[website]['Password:'] = encryptedPass #password key in website dictionary
            print("Password updated successfully.")
        if choice == 3:
            url = input("Please enter a new url for %s: " % website)
            entries[website]['URL:'] = url  #url key updated
            print("URL updated successfully.")
        writeFile = open(password_file_name, 'wb')
        pickle.dump(entries, writeFile)     #updates pickle file
        writeFile.close()
    else:
        print("No entry found for %s" % website)
        pass

def delete_entry():
    print("What website would you like to remove?")
    website = input()
    entries = load_entries()
    if website in entries:      #checks if entry is in dictionary
        entries.pop(website)    #removes entry from dictionary
    else:
        print("Entry not found...")
    writeFile = open(password_file_name, 'wb')
    pickle.dump(entries, writeFile)     #saves dictionary
    print("Entry deleted.")
    writeFile.close()

def switcher(i):
    menu_dict = {
        1 : print_entries,
        2 : lookup_password,
        3 : add_entry,
        4 : edit,
        5 : delete_entry,
        6 : save_password_file,
        7 : print_entries,
        8 : sys.exit
        }
    func = menu_dict.get(i, lambda : 'Invalid')     #sets function to dictionary choice
    return func()                                   #returns chosen function

while True:
    print(menu_text)
    choice = int(input())
    switcher(choice)        #runs function chosen by user
