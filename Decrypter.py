import tkinter as tk
from Encrypter import Encrypter
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from tkinter.messagebox import showinfo, askyesno


class Decrypter():

    def __init__(self):
        
        ''' Initializes key entry window'''
      
        self.word_check = 'safeword' # Constant
        self.encrypted_path = r"C:\Users\arash\Documents\python projects\AdvancedEncrypter\EncryptedPasswords.txt"
      
        self.KeyWindow()
        try:
            self.PasswordWindow()
        except:
            self.root.destroy()
            self.stop_condition = False
            return
        self.stop_condition = True


    def KeyWindow(self):

        ''' Prompts user to enter string password as input'''

        # Key window
        self.key_window = tk.Tk()
        self.key_window.title("Decryption Key")
        self.key_window.protocol("WM_DELETE_WINDOW", self.OnClosing)

        # Key label
        self.key_label = tk.Label(self.key_window, text="Key:")
        self.key_label.grid(row=0, column= 0, padx= 10, pady= 10)

        # Key entry
        self.key_entry = tk.Entry(self.key_window, width= 50)
        self.key_entry.grid(row=0, column= 1, padx= 10, pady= 10)
        self.key_entry.bind("<Return>", lambda e: self.KeyEntered())

        self.key_window.mainloop()


    def KeyEntered(self) -> None:

        ''' Checks for valid encryptions password and
            moves on to main password window '''

        self.key_entry.configure(background= "white")

        try:
            salt = b'2\xc5x\x9c\x02|\xc1|\x1d\xa4u?7\xcet\x13G\xa9\x8c\xfaAw\x97\x05\xdcP>\x81\x99>\xc7\x86' # constant

            kdf = PBKDF2HMAC(
                algorithm= hashes.SHA256(),
                length= 32,
                salt= salt,
                iterations= 500_000
            )

            input_key = self.key_entry.get() # str
            intput_byte = input_key.encode('utf-8') # str -> byte

            pw_key = base64.urlsafe_b64encode(kdf.derive(intput_byte))
            self.key = pw_key
            self.decrypter = Fernet(pw_key)

        except:
            self.key_entry.configure(background= "red")
            return
        
        self.key_window.destroy()
        return
        

    def PasswordWindow(self):
        
        ''' Main password window where text is decrypted
            double clicking highlights info '''

        self.root = tk.Tk()
        self.root.title("Decrypted Passwords")

        # Create listbox frame with scrollbar
        self.list_frame = tk.Frame(self.root)
        self.list_scrollbar = tk.Scrollbar(self.list_frame, orient= tk.VERTICAL)
        self.list_box = tk.Listbox(self.list_frame, width= 60, yscrollcommand= self.list_scrollbar.set)
        self.list_box.bind("<Double-Button-1>", lambda e: self.DoubleClick())
        self.list_scrollbar.config(command= self.list_box.yview)
        self.list_scrollbar.pack(side= tk.RIGHT, fill= tk.Y)
        self.list_box.pack()
        self.list_frame.grid(row= 0, column= 0, columnspan= 3)

        # Decrypt text
        self.DecryptText()

        # Add apps to list box
        self.RefreshListbox()

        # Add button
        self.add_btn = tk.Button(self.root, text= "Add", width= 15, state= tk.NORMAL, command= lambda: self.AddButton())
        self.add_btn.grid(row= 1, column= 0)

        # Edit button
        self.edit_btn = tk.Button(self.root, text= "Edit", width= 15, state= tk.NORMAL, command= lambda: self.EditButton())
        self.edit_btn.grid(row= 1, column= 1)

        # Exit button
        self.exit_btn = tk.Button(self.root, text= "Exit", width= 15, command= lambda: self.ExitProgram())
        self.exit_btn.grid(row= 1, column= 2)

        self.root.mainloop()

    def DecryptText(self):
        
        ''' Reads in encrypted file and decrypts information using
            provided key. Creates/Updates variables;
            - encrypted_string
            - encrypted_list
            - decrypted_list
            - decrypted_dict '''

        # Read in encrypted binary string
        with open(self.encrypted_path, 'rb') as text:
            self.encrypted_string = text.read()

        self.encrypted_list = self.encrypted_string.splitlines() # byte list
        self.decrypted_list = [] # string list

        # Decrypt
        for word in self.encrypted_list:
            if word != b'':
                self.decrypted_list.append(self.decrypter.decrypt(word).decode('utf-8')) # Raises error if input pw is wrong
            else:
                self.decrypted_list.append("")

        assert len(self.encrypted_list) % 4 == 0 # fails if encrypted file is modified externally

        self.n_apps = len(self.encrypted_list) // 4
        self.safe_word = self.decrypted_list[0]
        self.decrypted_list = self.decrypted_list[1:]
        
        # Check safe word (extra safety meassure)
        if self.safe_word != self.word_check:
            raise InterruptedError("Safeword was not correct")

        # Format into dictionary
        self.decrypted_dict = {}

        for app_i in range(self.n_apps):
            app = self.decrypted_list[4*app_i]
            user = self.decrypted_list[4*app_i+1]
            pw = self.decrypted_list[4*app_i+2]
            self.decrypted_dict[app] = [user, pw]

    def RefreshListbox(self):

        ''' Clear listbox entries and uses updated
            decrypted_dict variable to re-insert
            app entries into listbox '''

        self.list_box.delete(0, tk.END) # clear list box
        for app in self.decrypted_dict.keys():
            self.list_box.insert(tk.END, app)

    def DoubleClick(self):
        
        app = self.list_box.get(tk.ANCHOR) # highlighted app
        app_info = self.decrypted_dict[app]
        showinfo(title= str(app)+" info", message= f"u/@: {app_info[0]} \n pw: {app_info[1]}")
        return


    def ExitProgram(self):  
        self.stop_condition = True  
        self.root.destroy()
        return

    def AddButton(self):

        self.add_window = tk.Tk()

        ## Row 0 ##
        app_label = tk.Label(self.add_window, text= "App: ")
        app_label.grid(row=0, column= 0)

        self.app_entry = tk.Entry(self.add_window, width= 30)
        self.app_entry.grid(row=0, column= 1)

        ## Row 1 ##
        user_label = tk.Label(self.add_window, text= "u/@: ")
        user_label.grid(row=1, column= 0)

        self.user_entry = tk.Entry(self.add_window, width= 30)
        self.user_entry.grid(row=1, column= 1)
        
        ## Row 2 ##
        pw_label = tk.Label(self.add_window, text= "pw: ")
        pw_label.grid(row=2, column= 0)

        self.pw_entry = tk.Entry(self.add_window, width= 30)
        self.pw_entry.grid(row=2, column= 1)

        ## Row 3 ##
        submit_btn = tk.Button(self.add_window, text= "Encrypt", width= 25, command= lambda: self.AddAppend())
        submit_btn.grid(row= 3, column=0, columnspan= 2)

        self.add_window.mainloop()

    def AddAppend(self):
        
        self.app_entry.configure(background= 'white')
        self.user_entry.configure(background= 'white')
        self.pw_entry.configure(background= 'white')

        app, user, pw = self.app_entry.get(), self.user_entry.get(), self.pw_entry.get()
    
        err = False

        if app == "":
            self.app_entry.configure(background= 'red')
            err = True
        if user == "":
            self.user_entry.configure(background= 'red')
            err = True
        if pw == "":
            self.pw_entry.configure(background= 'red')
            err = True
        if err:
            return

        answer = askyesno("Add appinfo", f"Do you want to add the app  '{app}' with \n user/@: {user} \n pw: {pw}")

        if answer:
            self.encrypted_list.append(b'')
            self.encrypted_list += list(map(lambda word: self.decrypter.encrypt(bytes(word,'utf-8')), [app, user, pw]))
            self.add_window.destroy()
            self.UpdateEncryptionFile()
            self.DecryptText()
            self.RefreshListbox()
        else:
            self.add_window.destroy()

        return

    def EditButton(self):

        ''' Creates window to edit selected app.
            Calls UpdateEdit when btn is pressed '''

        app = self.list_box.get(tk.ANCHOR) # highlighted app
        user, pw = self.decrypted_dict[app]

        self.edit_index = 4*(self.list_box.curselection()[0])

        self.edit_window = tk.Tk()

        ## Row 0 ##
        app_label = tk.Label(self.edit_window, text= "App: ")
        app_label.grid(row=0, column= 0)

        self.edit_app_entry = tk.Entry(self.edit_window, width= 30)
        self.edit_app_entry.insert(0, app)
        self.edit_app_entry.grid(row=0, column= 1)

        ## Row 1 ##
        user_label = tk.Label(self.edit_window, text= "u/@: ")
        user_label.grid(row=1, column= 0)

        self.edit_user_entry = tk.Entry(self.edit_window, width= 30)
        self.edit_user_entry.insert(0, user)
        self.edit_user_entry.grid(row=1, column= 1)
        
        ## Row 2 ##
        pw_label = tk.Label(self.edit_window, text= "pw: ")
        pw_label.grid(row=2, column= 0)

        self.edit_pw_entry = tk.Entry(self.edit_window, width= 30)
        self.edit_pw_entry.insert(0, pw)
        self.edit_pw_entry.grid(row=2, column= 1)

        ## Row 3 ##
        edit_btn = tk.Button(self.edit_window, text= "Confirm edit", width= 25, command= lambda: self.UpdateEdit())
        edit_btn.grid(row= 3, column=0, columnspan= 2)

        self.edit_window.mainloop()

    def UpdateEdit(self):

        ''' Overwrites edit information in decrypted_list and
            encrypts information to encrypt_path '''

        app, user, pw = self.edit_app_entry.get(), self.edit_user_entry.get(), self.edit_pw_entry.get()
        
        err = False

        if app == "":
            self.edit_app_entry.configure(background= 'red')
            err = True
        if user == "":
            self.edit_user_entry.configure(background= 'red')
            err = True
        if pw == "":
            self.edit_pw_entry.configure(background= 'red')
            err = True
        if err:
            return

        edited_info = [app, user, pw]
        self.decrypted_list[self.edit_index: self.edit_index+3] = edited_info # overwrite with new edited info
        _ = Encrypter(self.key, [self.word_check, *self.decrypted_list]) # re-encrypt edited
        self.DecryptText()
        self.RefreshListbox()
        self.edit_window.destroy()

    def UpdateEncryptionFile(self):

        ''' Writes current encrypted_list to 
            file in encrypted_path
        '''

        new_encrypted_string = b'\n'.join(self.encrypted_list) # binary string
        with open(self.encrypted_path,'wb') as text:
            text.write(new_encrypted_string)

    def OnClosing(self):
        self.key_window.destroy()
        exit(0)


if __name__ == "__main__":

    while True:
        decrypter = Decrypter()
        if decrypter.stop_condition:
            exit(0)
        del decrypter