# A password cracker using pwntools and the wordlists found in Kali.

from pwn import crypt


def testPass(cryptPass):
    salt = cryptPass[:2]
    dictFile = open('dictionary.txt', 'r')
    for word in dictFile:
        word = word.strip('\n')
        cryptWord = crypt.crypt(word, salt)
        if cryptWord == cryptPass:
            print(f"[+] Found Password: {word}")
            return
    print("[-] Password Not Found.")
    return


def main():
    passFile = open('passwords.txt')
    for line in passFile:
        if ":" in line:
            user = line.split(':')[0]
            cryptPass = line.split(':')[1].strip(' ')
            print(f"[*] Cracking Password For: {user}")
            testPass(cryptPass)


if __name__ == "__main__":
    main()

# As you can see, this program is very simple. It opens the passwords.txt
# file and reads each line. Then, it splits the line into two pieces, the
# username and the encrypted password. The program then calls the testPass
# function and passes the encrypted password as a parameter. The testPass
# function then opens the dictionary.txt file and loops through each line.
# It strips the newline character and then encrypts the word using the salt
# from the encrypted password. If the encrypted word matches the encrypted
# password, the program prints out the password and exits. If the program
# reaches the end of the dictionary file and no matches are found, the program
# prints out that the password was not found.
#
# The passwords.txt file is a list of usernames and encrypted passwords.
# The encrypted passwords are generated using the crypt() function in Python.
# The crypt() function takes two parameters, the password and the salt.
# The salt is the first two characters of the encrypted password. The salt is
# used when encrypting the password. The salt is used to make it harder to
# crack the password. The salt is stored with the encrypted password so that
# the program knows which salt to use when encrypting the password.
#
# The dictionary.txt file is a list of common passwords. This file is used to
# try and crack the passwords. The dictionary file is a list of words that are
# commonly used as passwords. The program will try each word in the dictionary
# file and see if it matches the encrypted password. If the password is found,
# the program will print the password and exit.
#
# The program will loop through each line in the passwords.txt file and try to
# crack
