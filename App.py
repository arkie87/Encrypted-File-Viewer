import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tkinter import Tk, Label, Button, Entry, Text, StringVar, Scrollbar, filedialog, ttk, BOTH, LEFT, RIGHT, TOP, BOTTOM, Y, END


FILEDIR = os.path.dirname(__file__)


class App:
    def __init__(self):
        self.window = Tk()
        self.window.title("Arkie's Encrypted File Viewer 1.0")
        self.window.geometry("1200x800")
        
        Label(self.window, text="Enter Password").pack(side=TOP, anchor='nw')
        
        self.textvar = StringVar()
        self.password_entry = Entry(self.window, textvariable=self.textvar)
        self.password_entry.pack(side=TOP, anchor='nw')
        
        self.warningvar = StringVar()
        self.label = Label(self.window, textvariable=self.warningvar)
        self.label.pack(side=TOP, anchor='nw')
        
        self.decrypt_btn = Button(self.window, text='Decrypt', command=self.decrypt)
        self.decrypt_btn.pack(side=LEFT, anchor='nw')
        self.encrypt_btn = Button(self.window, text='Encrypt', command=self.encrypt)
        self.encrypt_btn.pack(side=RIGHT, anchor='ne')
        
        self.scrollbar = Scrollbar(self.window)
        self.scrollbar.pack(side=RIGHT,fill=Y)
        
        self.entry = Text(self.window,width=400,height=450,yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.entry.yview)
        self.entry.pack(fill=BOTH)
        
        self.file = None
        self.key = None
        self.fernet = None

        self.window.mainloop()

    def decrypt(self):
        self.clear()
        self.file = filedialog.askopenfile(initialdir=FILEDIR).name
        with open(self.file, 'rb') as f:
            encrypted_text = f.read().replace(b"\r", b"")  # Remove Extra Returns that Appear?
        self.fernet = self.getkey()
        try:
            text = self.fernet.decrypt(encrypted_text)
            self.warningvar.set("")
            self.insert(text)
        except:
            self.warningvar.set("Invalid Password.")
        
    def clear(self):
        self.entry.delete(1.0, END)
        
    def insert(self, text):
        self.entry.insert(END, text)
        
    def encrypt(self):
        if self.file is None:
            self.file = filedialog.asksaveasfile(initialdir=FILEDIR).name
        text = bytes(self.entry.get(1.0, END), 'utf-8')
        if self.fernet is None or self.password != "":
            self.fernet = self.getkey()
        encrypted_text = self.fernet.encrypt(text)
        with open(self.file, 'wb') as f:
            f.write(encrypted_text)
            
    def getkey(self):
        password = bytes(self.password, 'utf-8')
        self.password_reset()
        kdf = PBKDF2HMAC(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=b'\x1a*\xaf\xef\x01\xbb\xdf>\xcd,\xa1zC)\xbb\xfb',
                            iterations=390000,
                        )
        self.key = base64.urlsafe_b64encode(kdf.derive(password))
        return Fernet(self.key)
        
    @property
    def password(self):
        return self.textvar.get()
        
    def password_reset(self):
        self.textvar.set("")


if __name__ == "__main__":
    app = App()
