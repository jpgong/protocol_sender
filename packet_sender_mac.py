# coding=utf-8
import tkinter
from tkinter import *
from tkinter import messagebox
from tkinter.constants import *
from tkinter.ttk import Treeview

from scapy.all import *
from scapy.layers.l2 import Ether, ARP

tk = tkinter.Tk()
tk.title("协议编辑器")
tk.geometry("700x600")
# 左右分隔窗体
main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5)
# 协议编辑区窗体
protocol_editor_panedwindow = PanedWindow(orient=VERTICAL)
# 协议导航树
protocols_tree = Treeview()


def create_protocols_tree():
    """
    创建协议导航树
    :return: 协议导航树
    """
    protocols_tree.heading('#0', text='选择网络协议', anchor='w')
    # 参数:parent, index, iid=None, **kw (父节点，插入的位置，id，显示出的文本)
    # 应用层
    applicatoin_layer_tree_entry = protocols_tree.insert("", 0, "应用层", text="应用层")  # ""表示父节点是根
    http_packet_tree_entry = protocols_tree.insert(applicatoin_layer_tree_entry, 1, "HTTP包", text="HTTP包")
    dns_packet_tree_entry = protocols_tree.insert(applicatoin_layer_tree_entry,1,"DNS包",text="DNS包")
    # 传输层
    transfer_layer_tree_entry = protocols_tree.insert("", 1, "传输层", text="传输层")
    tcp_packet_tree_entry = protocols_tree.insert(transfer_layer_tree_entry, 0, "TCP包", text="TCP包")
    upd_packet_tree_entry = protocols_tree.insert(transfer_layer_tree_entry, 1, "UDP包", text="UDP包")
    # 网络层
    ip_layer_tree_entry = protocols_tree.insert("", 2, "网络层", text="网络层")
    ip_packet_tree_entry = protocols_tree.insert(ip_layer_tree_entry, 0, "IP包", text="IP包")
    icmp_packet_tree_entry = protocols_tree.insert(ip_layer_tree_entry, 1, "ICMP包", text="ICMP包")
    arp_packet_tree_entry = protocols_tree.insert(ip_layer_tree_entry,2,"ARP包",text="ARP包")
    # 网络接入层
    ether_layer_tree_entry = protocols_tree.insert("", 3, "网络接入层", text="网络接入层")
    mac_frame_tree_entry = protocols_tree.insert(ether_layer_tree_entry, 1, "MAC帧", text="MAC帧")
    protocols_tree.bind('<<TreeviewSelect>>', on_click_protocols_tree)
    protocols_tree.pack()
    return protocols_tree


def on_click_protocols_tree(event):
    """
    协议导航树单击事件响应函数
    :param event: TreeView单击事件
    :return: None
    """
    selected_item = event.widget.selection()  # event.widget获取Treeview对象，调用selection获取选择对象名称
    # 清空protocol_editor_panedwindow上现有的控件
    for widget in protocol_editor_panedwindow.winfo_children():
        widget.destroy()

    if selected_item[0] == "MAC帧":
        create_mac_sender()
    elif selected_item[0] == "ARP包":
        pass
    elif selected_item[0] == "IP包":
        pass
    elif selected_item[0] == "TCP包":
        pass
    elif selected_item[0] == "UDP包":
        pass
    elif selected_item[0] == "HTTP包":
        pass


def create_protocol_editor(root, field_names):
    """
    创建协议字段编辑区
    :param root: 协议编辑区
    :param field_names: 协议字段名列表
    :return: 协议字段编辑框列表
    """
    entries = []
    for field in field_names:
        row = Frame(root)
        label = Label(row, width=15, text=field, anchor='e')
        entry = Entry(row, font=('Courier', '12', 'bold'))  # 设置编辑框为等宽字体
        row.pack(side=TOP, fill=X, padx=5, pady=5)
        label.pack(side=LEFT)
        entry.pack(side=RIGHT, expand=YES, fill=X)
        entries.append(entry)
    return entries


def clear_protocol_editor(entries):
    """
    清空协议编辑器的当前值
    :param entries: 协议字段编辑框列表
    :return: None
    """
    for entry in entries:
        entry.delete(0, END)


def create_bottom_buttons(root):
    """
    创建发送按钮和重置按钮
    :param root: 编辑编辑区
    :return: 发送按钮和清空按钮
    """
    bottom_buttons = Frame(root)
    send_packet_button = Button(bottom_buttons, width=20, text="发送")
    default_packet_button = Button(bottom_buttons, width=20, text="默认值")
    reset_button = Button(bottom_buttons, width=20, text="重置")
    bottom_buttons.pack(side=BOTTOM, fill=X, padx=5, pady=5)
    send_packet_button.grid(row=0, column=0, padx=5, pady=5)
    default_packet_button.grid(row=0, column=1, padx=2, pady=5)
    reset_button.grid(row=0, column=2, padx=5, pady=5)
    bottom_buttons.columnconfigure(0, weight=1)
    bottom_buttons.columnconfigure(1, weight=1)
    bottom_buttons.columnconfigure(2, weight=1)
    return send_packet_button, reset_button, default_packet_button


def create_mac_sender():
    """
    创建MAC帧编辑器
    :return: None
    """
    # MAC帧编辑区
    mac_fields = '源MAC地址：', '目标MAC地址：', '协议类型：'
    entries = create_protocol_editor(protocol_editor_panedwindow, mac_fields)
    send_packet_button, reset_button, default_packet_button = create_bottom_buttons(protocol_editor_panedwindow)
    # 为"回车键"的Press事件编写事件响应代码，发送MAC帧
    tk.bind('<Return>', (lambda event, e=entries: send_mac_frame(e)))  # <Return>代表回车键
    # 为"发送"按钮的单击事件编写事件响应代码，发送MAC帧
    send_packet_button.bind('<Button-1>', (lambda event, e=entries: send_mac_frame(e)))  # <Button-1>代表鼠标左键单击
    # 为"清空"按钮的单击事件编写事件响应代码，清空协议字段编辑框
    reset_button.bind('<Button-1>', (lambda event, e=entries: clear_protocol_editor(e)))
    # 为"默认值"按钮的单击事件编写事件响应代码，在协议字段编辑框填入MAC帧字段的默认值
    default_packet_button.bind('<Button-1>', (lambda event, e=entries: create_default_mac_frame(e)))


def create_default_mac_frame(entries):
    """
    在协议字段编辑框中填入默认MAC帧的字段值
    :param entries: 协议字段编辑框列表
    :return: None
    """
    clear_protocol_editor(entries)
    default_mac_frame = Ether()
    entries[0].insert(0, default_mac_frame.src)
    entries[1].insert(0, default_mac_frame.dst)
    entries[2].insert(0, hex(default_mac_frame.type))


def send_mac_frame(entries):
    """
    发送MAC帧
    :param entries:协议字段编辑框列表
    :return: None
    """
    if entries[0].get() != '' and entries[1].get() != '' and entries[2].get() != '':
        mac_src = entries[0].get()
        mac_dst = entries[1].get()
        mac_type = int(entries[2].get(), 16)
        mac_frame = Ether(src=mac_src, dst=mac_dst, type=mac_type)
        print(mac_frame.show())
        n = send(mac_frame, return_packets=True).__len__()
        print('共发送了' + str(n) + "个MAC帧")
        # messagebox.showinfo('成功', '共发送了' + str(n) + "个MAC帧")

def create_welcome_page(root):
    welcome_string = '巨丑的封面\n计算机网络课程设计\n协议编辑器\n学号：\n姓名：'
    label2 = Label(root, justify=CENTER, padx=10, pady=150, text=welcome_string,
                   font=('隶书', '30', 'bold')).pack()



if __name__ == '__main__':
    # 创建协议导航树并放到左右分隔窗体的左侧
    main_panedwindow.add(create_protocols_tree())
    # 将协议编辑区窗体放到左右分隔窗体的右侧
    main_panedwindow.add(protocol_editor_panedwindow)
    # 创建MAC帧编辑器
    create_welcome_page(protocol_editor_panedwindow)
    main_panedwindow.pack(fill=BOTH, expand=1)
    # 启动消息处理
    tk.mainloop()
