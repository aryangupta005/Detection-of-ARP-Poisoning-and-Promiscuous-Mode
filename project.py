import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import *
from PIL import ImageTk, Image
from scapy.all import Ether, ARP, srp, sniff, conf
import threading
import psutil

def get_mac(ip):
    p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
    result = srp(p, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc

def process(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        try:
            real_mac = get_mac(packet[ARP].psrc)
            response_mac = packet[ARP].hwsrc
            if real_mac != response_mac:
                g.delete(0, 'end')
                g.insert(0, 'YOU ARE BEING ATTACKED')
                e.set()
        except IndexError:
            pass

def sniffs(e):
    g.delete(0, 'end')
    iface = variable.get()
    sniff(store=False, prn=process, iface=iface, timeout=15, stop_filter=lambda p: e.is_set())
    if not e.is_set():
        g.insert(0, 'YOU ARE SAFE')
    e.clear()

def promiscs(e1):
    y.delete(0, 'end')
    ip = e1.get()
    if ip == "":
        y.insert(0, 'ENTER IP')
        return
    try:
        t = get_macs(ip)
        y.insert(0, 'ON')
    except:
        y.insert(0, 'OFF')

def get_macs(ip):
    promisc_test = Ether(dst='01:00:00:00:00:00')/ARP(pdst=ip)
    result = srp(promisc_test, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc

def open_Toplevel1():
    top1 = Toplevel(bg='#0e0d30')
    top1.title("ARP POISONING")
    top1.geometry("400x250")

    style = ttk.Style()
    style.configure('W.TButton', font=('calibri', 10, 'bold', 'underline'), foreground='red')

    label = Label(top1, text="ARP POISONING", font='Serif 18 bold', foreground="lightgreen", background="#0e0d30")
    label.pack(pady=10)
    
    label = Label(top1, text="Specify interface:", background="#0e0d30", foreground="lightgreen")
    label.place(relx=0.1, rely=0.22, relheight=0.1, relwidth=0.3)
    
    global variable
    variable = StringVar(top1)
    variable.set(OPTIONS[0])
    
    w = OptionMenu(top1, variable, *OPTIONS)
    w.place(relx=0.5, rely=0.22, relheight=0.1, relwidth=0.3)
    
    button1 = ttk.Button(top1, text="Exit", style='W.TButton', command=top1.destroy)
    button1.place(relx=0.1, rely=0.5, relheight=0.1, relwidth=0.3)
    
    button = ttk.Button(top1, text="Start", command=lambda: threading.Thread(target=sniffs, args=[e]).start())
    button.place(relx=0.5, rely=0.5, relheight=0.1, relwidth=0.3)
    
    label = Label(top1, text="Result:", background="#0e0d30", foreground="lightgreen")
    label.place(relx=0.1, rely=0.8, relheight=0.1, relwidth=0.3)
    
    global g
    g = Entry(top1)
    g.place(relx=0.5, rely=0.8, relheight=0.12, relwidth=0.5)
    
    top1.mainloop()

def open_Toplevel2():
    top2 = Toplevel(bg='#0e0d30')
    top2.title("Promiscuous Mode")
    top2.geometry("450x250")

    style = ttk.Style()
    style.configure('W.TButton', font=('calibri', 10, 'bold', 'underline'), foreground='red')
    
    label = Label(top2, text="Promiscuous Mode", font='Serif 18 bold', background="#0e0d30", foreground="lightgreen")
    label.pack()
    
    label = Label(top2, text="IP Address:", background="#0e0d30", foreground="lightgreen")
    label.place(relx=0.1, rely=0.2, relheight=0.1, relwidth=0.3)
    
    e1 = Entry(top2)
    e1.place(relx=0.5, rely=0.2, relheight=0.1, relwidth=0.3)
    
    button1 = ttk.Button(top2, text="Exit", style='W.TButton', command=top2.destroy)
    button1.place(relx=0.1, rely=0.5, relheight=0.1, relwidth=0.3)
    
    button2 = ttk.Button(top2, text="Start", command=lambda: threading.Thread(target=promiscs, args=[e1]).start())
    button2.place(relx=0.5, rely=0.5, relheight=0.1, relwidth=0.3)
    
    label = Label(top2, text="Result:", background="#0e0d30", foreground="lightgreen")
    label.place(relx=0.1, rely=0.8, relheight=0.1, relwidth=0.3)
    
    global y
    y = Entry(top2, font='Serif 10 bold')
    y.place(relx=0.5, rely=0.8, relheight=0.1, relwidth=0.3)
    
    top2.mainloop()

# Create the root window
root = Tk()
root.configure(background="#0e0d30")
root.title("Minimalistic Tool")
root.geometry("600x500")

# Background Image
background_image = ImageTk.PhotoImage(file='imagess.jfif')
pic = Label(root, image=background_image)
pic.pack(fill="none", expand=True)

label1 = Label(root, text="Detection of Promiscuous Mode and ARP Poisoning", background="#000d1a", foreground="lightgreen", font="Serif 14 bold")
label1.pack(pady=10)

OPTIONS = ["----"] + [interface for interface in psutil.net_if_addrs()]
e = threading.Event()

# Create buttons to open toplevel windows
R1 = ttk.Button(root, text="PROMISCUOUS MODE", command=open_Toplevel2, cursor="target")
R1.pack(padx=40, pady=10, ipadx=40)

R2 = ttk.Button(root, text="ARP POISONING", command=open_Toplevel1, cursor="target")
R2.pack(padx=40, pady=10, ipadx=55)

# Message
ourMessage = '“Technology trust is a good thing, but control is a better one.”'
messageVar = Message(root, text=ourMessage, bg='lightgreen')
messageVar.pack()

root.mainloop()
