import tkinter
from tkinter import *

def calculate(event):
    result = eval(input_entry.get())
    output_label.config(text='计算结果'+str(result))
    print(result)
    #output_label.setvar(result)
    #print("hello world")

tk = tkinter.Tk()
tk.title("计算器")
input_entry = Entry(tk,width=80)
output_label = Label(tk,width=80, relief=SUNKEN)
button = Button(tk,text="计算")
input_entry.pack(side=TOP, fill=X, expand=YES)
output_label.pack(expand=YES, fill=X)
button.pack(side=BOTTOM)
button.bind("<Button-1>",calculate)
tk.mainloop()


