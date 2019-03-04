# coding=utf-8
import datetime
import threading
import tkinter
from tkinter import *
from tkinter import font, filedialog
from tkinter.constants import *
from tkinter.messagebox import askyesno
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Treeview
import easygui
import os

from scapy.layers.inet import *
from scapy.layers.l2 import *

#存储抓取到的数据帧
list=[]
#收到的数据帧数量
receved =0
#已经分析的数据帧数量
analysised=0
#停止标志位
stop_flag=False
#抓到的数据包
packet=NONE
#抓包线程
thread1=NONE
#暂停按钮值
pause_button_text="暂停"
#收包开始时间
begin_time=NONE
#已收包大小
total_bytes=0

# 状态栏类
class StatusBar(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self.label = Label(self, bd=1, relief=SUNKEN, anchor=W)
        self.label.pack(fill=X)

    def set(self, fmt, *args):
        self.label.config(text=fmt % args)
        self.label.update_idletasks()

    def clear(self):
        self.label.config(text="")
        self.label.update_idletasks()


# 时间戳转为格式化的时间字符串
def timestamp2time(timestamp):
    time_array = time.localtime(timestamp)
    mytime = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
    return mytime


def on_click_packet_list_tree(event):
    """
    数据包列表单击事件响应函数，在数据包列表单击某数据包时，在协议解析区解析此数据包，并在hexdump区显示此数据包的十六进制内容
    :param event: TreeView单击事件
    :return: None
    """
    selected_item = event.widget.selection()  # event.widget获取Treeview对象，调用selection获取选择对象名称
    # 清空packet_dissect_tree上现有的内容
    packet_dissect_tree.delete(*packet_dissect_tree.get_children())
    # 设置协议解析区的宽度
    packet_dissect_tree.column('Dissect', width=packet_list_frame.winfo_width())

    # !!!!!!!!!!!!!!!测试用的数据包!!!!!!!!!!!!!!要求换成你抓到的数据包!!!!!!!!!!!!!!!!!!!
    number = packet_list_tree.selection()
    number = str(number)
    number = re.sub("\D", "", number)
    number = int(number)
    packet = list[number-1]
    lines = (packet.show(dump=True)).split('\n')
    last_tree_entry = None
    for line in lines:
        if line.startswith('#'):
            line = line.strip('# ')
            last_tree_entry = packet_dissect_tree.insert('', 'end', text=line)
        else:
            packet_dissect_tree.insert(last_tree_entry, 'end', text=line)
        col_width = font.Font().measure(line)
        # 根据新插入数据项的长度动态调整协议解析区的宽度
        if packet_dissect_tree.column('Dissect', width=None) < col_width:
            packet_dissect_tree.column('Dissect', width=col_width)
    #!!!!!!!!!!!!!!!!此处没实现到抓到的数据包的校验和的检查!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    #!!!!!!!!!!!!!!!!要求在此处补充代码检查数据包校验包是否正确，包括TCP/UPD/IP包的校验和!!!!!!!!!!!
    # 在hexdump区显示此数据包的十六进制内容
    hexdump_scrolledtext['state'] = 'normal'
    hexdump_scrolledtext.delete(1.0, END)
    hexdump_scrolledtext.insert(END, hexdump(packet, dump=True))
    hexdump_scrolledtext['state'] = 'disabled'

# 测试在界面中显示一个数据包的内容
def just_a_test():
        # !!!!!!!!!!!!!!!测试用的数据包!!!!!!!!!!!!!!要求换成你抓到的数据包!!!!!!!!!!!!!!!!!!!
        '''
        packet = IP()/TCP(dport=80)
        packet_time = timestamp2time(packet.time)
        src = packet[IP].src
        dst = packet[IP].dst
        proto = 'http'
        length = len(packet)
        info = packet.summary()
        # print(info)
        packet_list_tree.insert("", 'end', '1', text='1', values=('1', packet_time, src, dst, proto, length, info))
        packet_list_tree.update_idletasks()
        packet1 = IP()/TCP(dport=443)
        packet_time1 = timestamp2time(packet1.time)
        src1 = packet1[IP].src
        dst1 = packet1[IP].dst
        proto1 = 'http'
        length1 = len(packet1)
        info1 = packet1.summary()
        # print(info)
        packet_list_tree.insert("", 'end', '2', text='2', values=('2', packet_time1, src1, dst1, proto1, length1, info1))
        packet_list_tree.update_idletasks()
        '''

# 将抓到的数据包保存为pcap格式的文件
def save_captured_data_to_file():
   global pkts
   wrpcap("temp.pcap",pkts)
   easygui.msgbox("保存完成")


# 开始按钮单击响应函数，如果是停止后再次开始捕获，要提示用户保存已经捕获的数据
def start_capture():
    global stop_flag
    global list
    global analysised
    global reversed
    global pause_button_text
    global begin_time
    if stop_flag==True:
        Yes_or_No = easygui.buttonbox("是否保存已抓取数据包?", choices = ['保存','不保存'])
        if Yes_or_No==True:
            global pkts
            wrpcap("temp.pcap",pkts)
        stop_flag=False

    #初始化变量
    list.clear()
    analysised=0
    receved=0
    items = packet_list_tree.get_children()
    [packet_list_tree.delete(item) for item in items]
    packet_list_tree.update_idletasks()
    pause_button_text="暂停"
    pause_button['text'] = pause_button_text
    # 创建新线程
    global  thread1
    thread1 = receve_thread(1, "Thread-1", 1)
    thread2 = analyse_thread(2, "Thread-2", 2)
    # 开启线程
    thread1.start()
    thread2.start()
    begin_time = datetime.datetime.now()

    pause_button['state'] = 'normal'
    stop_button['state'] = 'normal'



# 暂停按钮单击响应函数
def pause_capture():
   global pause_button_text
   if pause_button_text=="暂停":

       pause_button_text="继续"
       pause_button['text'] = pause_button_text
       return
   if pause_button_text=="继续":
       pause_button_text="暂停"
       pause_button['text'] = pause_button_text





# 停止按钮单击响应函数
def stop_capture():
    global  stop_flag

    stop_flag=True
    pause_button['state'] = 'disable'
    stop_button['state'] = 'disable'
    save_button['state'] = 'normal'
    status_bar.set("%s", '开始')


# 退出按钮单击响应函数,退出程序前要提示用户保存已经捕获的数据
def quit_program():
    os._exit(0)

def packet_append(packet):
    global receved
    global begin_time
    global total_bytes
    if pause_button_text == "暂停":
          list.append(packet)
          receved= receved + 1
          end_time = datetime.datetime.now()
          total_bytes=total_bytes+len(packet)
          bytes_per_second = total_bytes / ((end_time - begin_time).total_seconds()) / 1024
          status_bar.set('已经收到了%d个数据包, 已经收到了%d个字节，接受速率: %0.2fM字节/秒', receved, total_bytes, bytes_per_second)

def stop_sniff(packet):
    global stop_flag
    if stop_flag==True:
        return True
    if stop_flag==False:
        return False

# 读入线程
class receve_thread (threading.Thread):   #继承父类threading.Thread
    def __init__(self, threadID, name, counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
    def run(self):                   #把要执行的代码写到run函数里面 线程在创建后会直接运行run函数
        global pkts
        pkts=sniff(filter=fitler_entry.get(),prn=lambda x:packet_append(x),stop_filter= lambda x:stop_sniff(x))

#分析线程，并添加进页面
class analyse_thread (threading.Thread):   #继承父类threading.Thread
    def __init__(self, threadID, name, counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter

    def run(self):                   #把要执行的代码写到run函数里面 线程在创建后会直接运行run函数
        var=1
        global analysised
        while var==1:
            if(len(list)>analysised):
                #list[analysised].display()
                packet=list[analysised]
                analysised=analysised+1

                packet_time = timestamp2time(packet.time)
                src = packet.src
                dst = packet.dst
                proto_names = ['Ether','ARP','IP','IPv6','ICMP','TCP', 'UDP', 'Unknown']
                proto = ''
                for pn in proto_names:
                    if pn in packet:
                        proto = pn
                length = len(packet)
                info = packet.summary()
                # print(info)
                packet_list_tree.insert("", 'end', '%s'%(analysised), text=analysised, values=('%s'%(analysised), packet_time, src, dst, proto, length, info))
                packet_list_tree.update_idletasks()

            else:
                time.sleep(0.1)





# ---------------------以下代码负责绘制GUI界面---------------------
tk = tkinter.Tk()
tk.title("协议分析器")
# tk.resizable(0, 0)
# 带水平分割条的主窗体
main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5, orient=VERTICAL)

# 状态栏
status_bar = StatusBar(tk)
status_bar.pack(side=BOTTOM, fill=X)
status_bar.set("%s", '开始')

# 顶部的按钮及过滤器区
toolbar = Frame(tk)
start_button = Button(toolbar, width=8, text="开始", command=start_capture)
pause_button = Button(toolbar, width=8, text=pause_button_text, command=pause_capture)
stop_button = Button(toolbar, width=8, text="停止", command=stop_capture)
save_button = Button(toolbar, width=8, text="保存数据", command=save_captured_data_to_file)
quit_button = Button(toolbar, width=8, text="退出", command=quit_program)
start_button['state'] = 'normal'
pause_button['state'] = 'disable'
stop_button['state'] = 'disable'
save_button['state'] = 'disable'
quit_button['state'] = 'normal'
filter_label = Label(toolbar, width=10, text="BPF过滤器：")
fitler_entry = Entry(toolbar)
start_button.pack(side=LEFT, padx=5)
pause_button.pack(side=LEFT, after=start_button, padx=10, pady=10)
stop_button.pack(side=LEFT, after=pause_button, padx=10, pady=10)
save_button.pack(side=LEFT, after=stop_button, padx=10, pady=10)
quit_button.pack(side=LEFT, after=save_button, padx=10, pady=10)
filter_label.pack(side=LEFT, after=quit_button, padx=0, pady=10)
fitler_entry.pack(side=LEFT, after=filter_label, padx=20, pady=10, fill=X, expand=YES)
toolbar.pack(side=TOP, fill=X)

# 数据包列表区
packet_list_frame = Frame()
packet_list_sub_frame = Frame(packet_list_frame)
packet_list_tree = Treeview(packet_list_sub_frame, selectmode='browse')
packet_list_tree.bind('<<TreeviewSelect>>', on_click_packet_list_tree)
# 数据包列表垂直滚动条
packet_list_vscrollbar = Scrollbar(packet_list_sub_frame, orient="vertical", command=packet_list_tree.yview)
packet_list_vscrollbar.pack(side=RIGHT, fill=Y, expand=YES)
packet_list_tree.configure(yscrollcommand=packet_list_vscrollbar.set)
packet_list_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)
# 数据包列表水平滚动条
packet_list_hscrollbar = Scrollbar(packet_list_frame, orient="horizontal", command=packet_list_tree.xview)
packet_list_hscrollbar.pack(side=BOTTOM, fill=X, expand=YES)
packet_list_tree.configure(xscrollcommand=packet_list_hscrollbar.set)
# 数据包列表区列标题
packet_list_tree["columns"] = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
packet_list_column_width = [100, 180, 160, 160, 100, 100, 800]
packet_list_tree['show'] = 'headings'
for column_name, column_width in zip(packet_list_tree["columns"], packet_list_column_width):
    packet_list_tree.column(column_name, width=column_width, anchor='w')
    packet_list_tree.heading(column_name, text=column_name)
packet_list_tree.pack(side=LEFT, fill=X, expand=YES)
packet_list_frame.pack(side=TOP, fill=X, padx=5, pady=5, expand=YES, anchor='n')
# 将数据包列表区加入到主窗体
main_panedwindow.add(packet_list_frame)

# 协议解析区
packet_dissect_frame = Frame()
packet_dissect_sub_frame = Frame(packet_dissect_frame)
packet_dissect_tree = Treeview(packet_dissect_sub_frame, selectmode='browse')
packet_dissect_tree["columns"] = ("Dissect",)
packet_dissect_tree.column('Dissect', anchor='w')
packet_dissect_tree.heading('#0', text='Packet Dissection', anchor='w')
packet_dissect_tree.pack(side=LEFT, fill=BOTH, expand=YES)
# 协议解析区垂直滚动条
packet_dissect_vscrollbar = Scrollbar(packet_dissect_sub_frame, orient="vertical", command=packet_dissect_tree.yview)
packet_dissect_vscrollbar.pack(side=RIGHT, fill=Y)
packet_dissect_tree.configure(yscrollcommand=packet_dissect_vscrollbar.set)
packet_dissect_sub_frame.pack(side=TOP, fill=X, expand=YES)
# 协议解析区水平滚动条
packet_dissect_hscrollbar = Scrollbar(packet_dissect_frame, orient="horizontal", command=packet_dissect_tree.xview)
packet_dissect_hscrollbar.pack(side=BOTTOM, fill=X)
packet_dissect_tree.configure(xscrollcommand=packet_dissect_hscrollbar.set)
packet_dissect_frame.pack(side=LEFT, fill=X, padx=5, pady=5, expand=YES)
# 将协议解析区加入到主窗体
main_panedwindow.add(packet_dissect_frame)

# hexdump区
hexdump_scrolledtext = ScrolledText(height=10)
hexdump_scrolledtext['state'] = 'disabled'
# 将hexdump区区加入到主窗体
main_panedwindow.add(hexdump_scrolledtext)

main_panedwindow.pack(fill=BOTH, expand=1)

# 状态栏
status_bar = StatusBar(tk)
status_bar.pack(side=BOTTOM, fill=X)
just_a_test()
tk.mainloop()

