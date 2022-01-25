#==============================IMPORTS======================================
from tkinter import *
import sqlite3
    
condition = True
root = Tk()
root.title("INTRUSION DETECTION ")
width = 400
height = 280
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = (screen_width/2) - (width/2)
y = (screen_height/2) - (height/2)
root.geometry("%dx%d+%d+%d" % (width, height, x, y))
root.resizable(0, 0)

#==============================VARIABLES======================================
USERNAME = StringVar()
PASSWORD = StringVar()
    
#==============================FRAMES=========================================
Top = Frame(root, bd=2,  relief=RIDGE)
Top.pack(side=TOP, fill=X)
Form = Frame(root, height=200)
Form.pack(side=TOP, pady=20)

#==============================LABELS=========================================
lbl_title = Label(Top, text = "CYBER INTRUSION DETECTION SYSTEM", font=('arial', 14))
lbl_title.pack(fill=X)
lbl_username = Label(Form, text = "Username:", font=('arial', 14), bd=15)
lbl_username.grid(row=0, sticky="e")
lbl_password = Label(Form, text = "Password:", font=('arial', 14), bd=15)
lbl_password.grid(row=1, sticky="e")
lbl_text = Label(Form)
lbl_text.grid(row=2, columnspan=2)     

#==============================ENTRY WIDGETS==================================
username = Entry(Form, textvariable=USERNAME, font=(14))
username.grid(row=0, column=1)
password = Entry(Form, textvariable=PASSWORD, show="*", font=(14))
password.grid(row=1, column=1)

#================================LOGIN METHOD===========================

def Login(event=None):
    Database()
    if USERNAME.get() == "" or PASSWORD.get() == "":
        lbl_text.config(text="Please complete the required field!", fg="red")
    else:
        cursor.execute("SELECT * FROM `member` WHERE `username` = ? AND `password` = ?", (USERNAME.get(), PASSWORD.get()))
        if cursor.fetchone() is not None:
            HomeWindow()
            USERNAME.set("")
            PASSWORD.set("")
            lbl_text.config(text="")
        else:
            lbl_text.config(text="Invalid username or password", fg="red")
            USERNAME.set("")
            PASSWORD.set("")   
    cursor.close()
    conn.close()
    
#==============================BUTTON WIDGETS=================================
btn_login = Button(Form, text="Login", width=45, command=Login)
btn_login.grid(pady=25, row=3, columnspan=2)
btn_login.bind('<Return>', Login)


#==============================METHODS========================================
def Database():
    USERNAME = "hacker" ; PASSWORD = "hacker123"
    global conn, cursor
    conn = sqlite3.connect("login.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS `member` (mem_id INTEGER NOT NULL PRIMARY KEY  AUTOINCREMENT, username TEXT, password TEXT)")       
    eval('''cursor.execute("SELECT * FROM `member` WHERE `username` = '%s' AND `password` = '%s'")'''%(USERNAME,PASSWORD))
    if cursor.fetchone() is None:
        eval('''cursor.execute("INSERT INTO `member` (username, password) VALUES('%s', '%s')")'''%(USERNAME,PASSWORD))
        conn.commit()
     
def HomeWindow():
    global Home
    root.withdraw()
    Home = Toplevel()
    Home.title("INTRUSION DETECTION")
    width = 600
    height = 400
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)
    root.resizable(0, 0)
    Home.geometry("%dx%d+%d+%d" % (width, height, x, y))
    lbl_home = Label(Home, text="Successfully Login!", font=('times new roman', 30)).pack()
    btn_back = Button(Home, text='CONTINUE',width = 80, command=go_on).pack(pady=20, fill=X)
     
def go_on():
    global condition    
    Home.destroy()
    condition = False
    #root.deiconify()

def main():
    while condition:
        root.update_idletasks() 
        root.update()
    
#==============================INITIALIATION==================================

if __name__ == '__main__':
    #root.mainloop()
    main()

