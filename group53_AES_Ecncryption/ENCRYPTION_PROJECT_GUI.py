'''
Team Members:
Olebogeng Moremi
Kopano Mere
Orateng
Oaratwa
Shane
'''

#Importing the libraries
import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES
import os
import time
import shutil
import hashlib
import zipfile
from PIL import Image

# Using hashing algorithm called SHA256
h = hashlib.new("sha256")

#Creating the main window for the GUI
window = tk.Tk()
window.title("File Encryption Project")

#Setting the size of the window for the GUI
window.geometry("700x700")

#Initializing the path to null so that it can be accessed in other methods
path = ""

# An AES Encryptor Class that contains methods to encrypt and decrypt files
class AESencryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    #A method that does the process of encrypting
    def encrypt_file2(self, input_filename, output_filename=None):
        if not output_filename:
            output_filename = input_filename + '.enc'

        #Using the CBC Mode of the AES algorithm
        iv = os.urandom(AES.block_size)
        encryptor = AES.new(self.key, AES.MODE_CBC, iv)
        
        with open(input_filename, 'rb') as infile:
            with open(output_filename, 'wb') as outfile:
                outfile.write(iv)
                while True:
                    val = infile.read(8192)
                    if len(val) == 0:
                        break
                    elif len(val) % AES.block_size != 0:
                        val += b' ' * (AES.block_size - len(val) % AES.block_size)
                    outfile.write(encryptor.encrypt(val))

    #A method that does the whole process of decrypting
    def decrypt_file2(self, input_filename, output_filename=None):
        if not output_filename:
            output_filename = os.path.splitext(input_filename)[0]
        with open(input_filename, 'rb') as infile:
            iv = infile.read(AES.block_size)
            decryptor = AES.new(self.key, AES.MODE_CBC, iv)

            with open(output_filename, 'wb') as outfile:
                while True:
                    val2 = infile.read(8192)
                    if len(val2) == 0:
                        break
                    outfile.write(decryptor.decrypt(val2))

        with open(output_filename, 'rb') as f:
            f.seek(16)
            encrypted_key = f.read(32) #The bytes of the secret key
            decrypted_key = self.key.decode('utf-8')

            #if decrypted_key != encrypted_key:
                #message_list.insert(tk.END, "The secret key is incorrect")

        #Displaying a message when the file has been decrypted
        message_list.insert(tk.END, "File successfully decrypted with the AES generic algorithm!")

#Decryption and Encryption part/functions for the Custom Algorithm
def encrypt(file_path):
    # Get the encryption key from the user
    key = input_textbox.get().encode('utf-8')

    # Update hash object with user input key
    h.update(key)
    key_hash = h.hexdigest()

    # Open the input file for reading
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Encrypt the file data
    alphabets = 'abcdefghijklmnopqrstuvwxyz'
    encrypted_data = bytearray()
    for data_byte in file_data:
        new_byte = data_byte
        if not data_byte == ord(' '):
            index = alphabets.find(chr(data_byte).lower())
            if index != -1:
                new_index = (index + 6) % 26
                new_byte = ord(alphabets[new_index])
        encrypted_data.append(new_byte)

    # Write the encrypted data to a new file
    encrypted_file_path = file_path + '.encrypted'
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_data)

    # Write the key hash to the password file
    with open('passwords.txt', 'a') as f:
        f.write(encrypted_file_path + ':' + key_hash + '\n')
    return encrypted_file_path

    # Encrypt text file
    file_path1 = file_path()
    encrypted_file_path = encrypt(file_path1)
    os.remove(file_path1)

    # Encrypt PowerPoint file
    file_path2 = file_path()
    encrypted_file_path = encrypt(file_path2)
    os.remove(file_path2)

    # Encrypt image file
    file_path3 = file_path()
    image = Image.open(file_path3)
    image_data = image.tobytes()
    encrypted_image_data = bytearray()
    for data_byte in image_data:
        new_byte = data_byte
        if not data_byte == ord(' '):
            index = alphabets.find(chr(data_byte).lower())
            if index != -1:
                new_index = (index + 6) % 26
                new_byte = ord(alphabets[new_index])
        encrypted_image_data.append(new_byte)
    encrypted_image_file_path = file_path3 + '.encrypted'
    
    with open(encrypted_image_file_path, 'wb') as f:
        f.write(encrypted_image_data)
    os.remove(file_path3)

    # Encrypt zip file
    file_path4 = file_path()
    with zipfile.ZipFile(file_path4, 'r') as zip_ref:
        zip_ref.extractall('temp_dir')
    temp_dir = 'temp_dir'
    for root, dirs, files in os.walk(temp_dir):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt(file_path)
            os.remove(file_path)
            
    zip_name, extension = os.path.splitext(file_path4)
    encrypted.zip_file = zip_name + '_encrypted' + extension

    with zipfile.ZipFile(encrypted_zip_file, 'w') as zip_ref:
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                zip_ref.write(file_path)

    os.remove('passwords.txt')
    os.remove(encrypted_zip_file)
    os.remove(file_path4)
    os.removedirs(temp_dir)

def decrypt(encrypted_file_path):
    key = input_textbox.get().encode('utf-8')
    h.update(key)
    key_hash = h.hexdigest()

    # Check if the key is correct
    with open('passwords.txt', 'r') as f:
        for line in f:
            if encrypted_file_path in line:
                if key_hash == line.split(':')[1].strip():
                    message_list.insert(tk.END, "Key is correct")
                    break
        else:
            message_list.insert(tk.END, "Key matched")
            return

    # Open the encrypted file for reading
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()

    # Decrypt the file data
    alphabets = 'abcdefghijklmnopqrstuvwxyz'
    decrypted_data = bytearray()
    for data_byte in encrypted_data:
        new_byte = data_byte
        if not data_byte == ord(' '):
            index = alphabets.find(chr(data_byte).lower())
            if index != -1:
                new_index = (index - 6) % 26
                new_byte = ord(alphabets[new_index])
        decrypted_data.append(new_byte)

    # Write the decrypted data to a new file
    original_file_path = encrypted_file_path[:-10] # remove the ".encrypted" extension
    with open(original_file_path, 'wb') as f:
        f.write(decrypted_data)

    # Remove the encrypted file
    #os.remove(encrypted_file_path)

    message_list.insert(tk.END, "File decrypted successfully")

    #Decrypting text file

    file_path1 = file_path()

    key1 = input_textbox.get().encode('utf-8')
    decrypt(file_path, key1)

    #Decrypting a PowerPoint
    
    file_path2 = file_path()
    key2 = input_textbox.get().encode('utf-8')
    decrypt(file_path2, key2)

    #Decrypting an image file
    file_path3 = fiel_path()
    key3 = input_textbox.get().encode('utf-8')
    decrypt(file_path3, key3)

    #Decrypting a zip file
    encrypted_zip_file_path = file_path()
    key4 = input_textbox.get().encode('utf-8')
    
    with zipfile.ZipFile(encrypted_zip_file_path, 'r') as zip_ref:
        zip_ref.extractall('temp_dir')
        temp_dir = 'temp_dir'
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                decrypt(file_path, key4)
        #os.remove(file_path)

    #Creating a new zip file with decrypted files

    zip_name, extension = os.path.splitext(encrypted_zip_file_path)
    decrypted_zip_file_path = zip_name + '_decrypted' + extension
    with zipfile.ZipFile(decrypted_zip_file_path, 'w') as zip_ref:
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
    zip_ref.write(file_path)

    #Removing temporary directory and password file
    os.remove('passwords.txt')
    os.remove(encrypted_zip_file_path)
    os.removedirs(temp_dir)

    message_list.insert(tk.END, "All files decrypted successfully and a new zip file with decrypted files was created")
    
#Function to browse for a file
def browse_file():
    global path
    file_name = filedialog.askopenfilename(filetypes = (('Image file', '*.jpg'), ('PowerPoint file', '*.pptx'), ('Plaintext file', '*.txt'), ('ZIP file', '*.zip'), ('Encrypted file', '*.enc'), ('ENCRYPTED_CUSTOM', '*.encrypted')))
    selected_file.delete(0, tk.END)
    path = file_name
    
    #Displaying the selected file in the listbox
    selected_file.insert(tk.END, file_name)

#Function to access the file path across other functions/methods
def file_path():
    global path
    return path

#2nd Function of Encrypting when the Encrypt button has been clicked
def encrypt_file():
    #Initialising the variables of the GUI controls
    algorithm = algorithm_var.get()
    message_list.delete(0, tk.END)
    input_textbox.get()

    #The selection statements for when the user has either chosen one of the radiobuttons of the algorithm method
    if algorithm == "AES":
        # CODE TO ENCRYPT THE SELECTED FILE
        aes = AESencryptor(input_textbox.get().encode('utf-8'))
        aes.encrypt_file2(file_path())

        # CODE TO DELETE/REMOVE OR EMPTY THE SELECTIONS AND CONTROLS IN THE GUI
        message_list.insert(tk.END, "File successfully encrypted with the AES generic algorithm")
        message_list.insert(tk.END, "Please keep the key secret safe with you and use it again when decrypting the file.")
        selected_file.delete(0, tk.END)
        algorithm_var.set(None)
        input_textbox.delete(0, tk.END)

        # DELETING THE ORIGINAL FILE FROM THE FOLDER
        os.remove(file_path())
        
    elif algorithm == "Custom":
        encrypt(file_path())
         
        message_list.insert(tk.END, "File sucessfully encrypted with the Custom algorithm")
        message_list.insert(tk.END, "Please keep the key secret and use it again when decrypting the file.")
        selected_file.delete(0, tk.END)
        algorithm_var.set(None)
        input_textbox.delete(0, tk.END)

        os.remove(file_path())
            
    else:
        message_list.insert(tk.END, "\nPlease select an algorithm to encrypt file.")

#The final encrypt function that uses the methods that encrypt 
def final_encrypt():
    secret_key = input_textbox.get().encode('utf-8')
    aes = AESencryptor(secret_key)
    encrypt_file()

#The final Decryption function that decrypts the files
def decrypt_file():

    #Initialising the variables of the GUI controls
    algorithm = algorithm_var.get()
    message_list.delete(0, tk.END)
    input_textbox.get()

    #The selection statements for when the user has either chosen one of the radiobuttons of the algorithm method
    if algorithm == "AES":
        # CODE TO ENCRYPT THE SELECTED FILE
        aes = AESencryptor(input_textbox.get().encode('utf-8'))
        aes.decrypt_file2(file_path())

        # CODE TO DELETE/REMOVE OR EMPTY THE SELECTIONS AND CONTROLS IN THE GUI
        selected_file.delete(0, tk.END)
        algorithm_var.set(None)
        input_textbox.delete(0, tk.END)

        # DELETING THE ORIGINAL FILE FROM THE FOLDER
        os.remove(file_path())
        
    elif algorithm == "Custom":
        decrypt(file_path())
        
        message_list.insert(tk.END, "File successfully decrypted with the Custom algorithm")
        selected_file.delete(0, tk.END)
        algorithm_var.set(None)
        input_textbox.delete(0, tk.END)

        # DELETING THE ORIGINAL FILE FROM THE FOLDER
        os.remove(file_path())
        
    else:
        message_list.insert(tk.END, "\nPlease select an algorithm to encrypt file.")


#Creating a label for the file input section
input_label = tk.Label(window, text="Insert File:", font=("Arial", 12, "bold"))
input_label.pack(pady=10)

#Creating a listbox to display the selected file
selected_file = tk.Listbox(window, height=3, width=35)
selected_file.pack(expand=False)

#Creating a button to browse for a file
browse_button = tk.Button(window, text="Browse", command=browse_file, font=("Arial", 10))
browse_button.pack(pady=25)

#Creating a textbox label for entering a password
password_label = tk.Label(window, text= "Secret Key", font=("Arial", 12, "bold"))
password_label.pack(pady=10)

#Creating a textbox to allow the user to enter the password

key_label = tk.Label(window, text="The Secret Key / Password should be 16 characters in length!", font=("Arial", 10, "bold"))
key_label.pack(pady=1)
key_label.configure(fg="red")

#Declaring and initialising the GUI controls
input_textbox = tk.Entry(window, width=35)
input_textbox.pack(pady=10)
secret_key = input_textbox.get().encode()
aes = AESencryptor(secret_key)

#Creating a label for the encryption algorithm selection section
algorithm_label = tk.Label(window, text="Choose an Algorithm:", font=("Arial", 12, "bold"))
algorithm_label.pack(pady=15)

#Creating a frame to hold the radiobuttons
algorithm_frame = tk.Frame(window)
algorithm_frame.pack()

#Creating two radiobuttons for selecting AES or Custom algorithm
algorithm_var = tk.StringVar(value = " ")
algorithm_var.set(" ")
aes_radio = tk.Radiobutton(algorithm_frame, text="AES", variable=algorithm_var, value="AES", font=("Arial", 12))
aes_radio.pack(pady=20)
custom_radio = tk.Radiobutton(algorithm_frame, text="Custom", variable=algorithm_var, value="Custom", font=("Arial", 12))
aes_radio.pack(side=tk.LEFT)
custom_radio.pack(side=tk.LEFT, padx=20)

#Creating a label for the process button section
process_label = tk.Label(window, text="Process File:", font=("Arial", 12, "bold"))
process_label.pack(pady=12)

#Creating a frame to hold the process buttons
process_frame = tk.Frame(window)
process_frame.pack()

#Creating two buttons for encrypting or decrypting the selected file
encrypt_button = tk.Button(process_frame, text="Encrypt", command=final_encrypt, font=("Arial", 12))
decrypt_button = tk.Button(process_frame, text="Decrypt", command=decrypt_file, font=("Arial", 12))
encrypt_button.pack(side=tk.LEFT)
decrypt_button.pack(side=tk.LEFT, padx=20, pady=20)

#Creating a label for the message section
message_label = tk.Label(window, text="Message:", font=("Arial", 12, "bold"))
message_label.pack(pady=10)

#Creating a listbox to display the message
message_list = tk.Listbox(window, height=6, width=35)
message_list.pack(pady=15, expand=False)

#Modifying the Listbox control in the GUI
message_list.config(width=75, height=50)
message_list.pack()

#Starting the main loop of the GUI and making it run/Display
window.mainloop()
