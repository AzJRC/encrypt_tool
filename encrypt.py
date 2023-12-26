from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
from os import listdir
from os.path import isfile, join

class Encryptor:
    def __init__(self, key = Random.get_random_bytes(16)):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size = 256):
        message = self.pad(message)
        init_vector = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, init_vector)
        return init_vector + cipher.encrypt(message)
    
    def encrypt_file(self, file_name):

        with open(file_name, 'rb') as f:
            plaintext = f.read()
        
        enc = self.encrypt(plaintext, self.key)
        with open(file_name + '.enc', 'wb') as f:
            f.write(enc)
        
        os.remove(file_name)

    def decrypt(self, ciphertext, key):
        init_vector = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, init_vector)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")
    
    def decrypt_file(self, file_name):

        with open(file_name, 'rb') as f:
            ciphertext = f.read()
        dec = self.decrypt(ciphertext, self.key)
        with open(file_name[:-4], 'wb') as f:
            f.write(dec)
        os.remove(file_name)

    def getAllFiles(self, dir_path):
        dirs = []
        for dirname, subdirlist, filelist in os.walk(dir_path):
            for fname in filelist:
                if (fname != 'encrypt.py' and fname != 'data.txt.enc'):
                    dirs.append(dirname+"\\"+fname)
        return dirs

    def encryptAllFiles(self, dir_path):
        dirs = self.getAllFiles(dir_path)
        for file_name in dirs:
            self.encrypt_file(file_name)

    def decryptAllFiles(self, dir_path):
        dirs = self.getAllFiles(dir_path)
        for file_name in dirs:
            self.decrypt_file(file_name)

key = b'\xddo\x1d\xea$\xa8\xb4\x99\x86\x0f\xa77l?\x92q'
enc = Encryptor(key)
clear = lambda: os.system('cls')
dir_path = os.path.dirname(os.path.realpath(__file__))

if os.path.isfile("data.txt.enc"):
    while True:
        password = str(input("Enter a password: "))
        enc.decrypt_file("data.txt.enc")
        p = ""
        with open("data.txt") as f:
            p = f.readlines()
        if p[0] == password:
            enc.encrypt_file("data.txt")
            break
    
    while True:
        clear()
        encrypt_option = int(input(
           f"""
[0] To exit the program.
[1] To encrypt a file.
[2] To decrypt a file.
[3] To encrypt all files in a directory.
[4] To decrypt all files in a directory.
[5] Locate in a different directory. (Current_dir = {dir_path})
            """
        ))
        clear()
        if encrypt_option == 0:
            exit()
        if encrypt_option == 1:
            enc.encrypt_file(str(input("Enter the file name or absolute path to encrypt: ")))
        if encrypt_option == 2:
            enc.decrypt_file(str(input("Enter the file name or absolute path to decrypt: ")))
        if encrypt_option == 3:
            enc.encryptAllFiles(dir_path)
        if encrypt_option == 4:
            enc.decryptAllFiles(dir_path)
        if encrypt_option == 5:
            new_dir_path = str(input("Enter absolute directory path: "))
            dir_path = new_dir_path if new_dir_path != "" else dir_path
        else:
            print("Incorrect option. Try again.")
    
else:
    while True:
        clear()
        password = str(input("Setup a password: "))
        repassword = str(input("Confirm your password: "))
        if password == repassword:
            break
        print("Password do not matched. Try again")
    
    with open("data.txt", "w") as f:
        f.write(password)
    enc.encrypt_file("data.txt")
    print("Password file successfully created. Run the program again.")
    