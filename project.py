from tkinter import *
import threading
from tkinter import messagebox
import psutil
from PIL import ImageTk, Image
from scapy.all import Ether, ARP, srp, sniff, conf

# Create the root window with specified size and title
root = Tk()
root.configure(background="#1c1c3c")
root.title("Network Security Tool")

# Configure root window size
root.geometry("600x400")

# Title Label
title_label = Label(root, text="Detection of Promiscuous Mode and ARP Poisoning", 
                    background="#000d1a", foreground="lightgreen", font="Serif 16 bold")
title_label.pack(pady=20)

# Background Image
background_image = ImageTk.PhotoImage(file='imagess.jfif')
pic = Label(root, image=background_image)
pic.pack(fill="both", expand=True)

# Network Interface Options
addrs = psutil.net_if_addrs()
OPTIONS = ["----"]
for interface in addrs:
    OPTIONS.append(interface)

def get_mac(ip):
    p = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip)
    result = srp(p, timeout=3, verbose=True)[0]
    return result[0][1].hwsrc

def process(packet):
    if packet.haslayer(ARP):
        if packet[ARP].op == 2:
            try:
                real_mac = get_mac(packet[ARP].psrc)
                response_mac = packet[ARP].hwsrc
                if real_mac != response_mac:
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
    try:
        y.delete(0, 'end')
        ip = e1.get()
        if ip == "":
            y.insert(0, 'ENTER IP')
            return
        t = get_macs(ip)
        y.insert(0, 'ON')
    except:
        y.insert(0, 'OFF')

def get_macs(ip):
    promisc_test = Ether(dst='01:00:00:00:00:00') / ARP(pdst=ip)
    result = srp(promisc_test, timeout=3, verbose=True)[0]
    return result[0][1].hwsrc

def open_Toplevel2():
    top2 = Toplevel(bg='#1c1c3c')
    top2.title("Promiscuous Mode")
    top2.geometry("500x300")
    
    label = Label(top2, text="Promiscuous Mode", font='Serif 18 bold', background="#1c1c3c", foreground="lightgreen")
    label.pack(pady=20)
    
    Label(top2, text="IP Address:", background="#1c1c3c", foreground="white").place(relx=0.1, rely=0.3, relheight=0.1, relwidth=0.3)
    e1 = Entry(top2)
    e1.place(relx=0.5, rely=0.3, relheight=0.1, relwidth=0.4)
    
    Button(top2, text="Exit", command=top2.destroy, cursor="X_cursor").place(relx=0.1, rely=0.6, relheight=0.1, relwidth=0.3)
    Button(top2, text="Start", command=lambda: threading.Thread(target=promiscs, args=[e1]).start(), cursor="spider").place(relx=0.5, rely=0.6, relheight=0.1, relwidth=0.4)
    
    Label(top2, text="Result:", background="#1c1c3c", foreground="white").place(relx=0.1, rely=0.8, relheight=0.1, relwidth=0.3)
    global y
    y = Entry(top2, font='Serif 10 bold')
    y.place(relx=0.5, rely=0.8, relheight=0.1, relwidth=0.4)
    
    top2.mainloop()

def open_Toplevel1():
    top1 = Toplevel(bg='#1c1c3c')
    top1.title("ARP Poisoning")
    top1.geometry("500x300")
    
    label = Label(top1, text="ARP Poisoning", font='Serif 18 bold', background="#1c1c3c", foreground="lightgreen")
    label.pack(pady=20)
    
    Label(top1, text="Specify Interface:", background="#1c1c3c", foreground="white").place(relx=0.1, rely=0.3, relheight=0.1, relwidth=0.4)
    global variable
    variable = StringVar(top1)
    variable.set(OPTIONS[0])
    
    w = OptionMenu(top1, variable, *OPTIONS)
    w.place(relx=0.5, rely=0.3, relheight=0.1, relwidth=0.4)
    
    Button(top1, text="Exit", command=top1.destroy, cursor="X_cursor").place(relx=0.1, rely=0.6, relheight=0.1, relwidth=0.3)
    Button(top1, text="Start", command=lambda: threading.Thread(target=sniffs, args=[e]).start(), cursor="spider").place(relx=0.5, rely=0.6, relheight=0.1, relwidth=0.4)
    
    Label(top1, text="Result:", background="#1c1c3c", foreground="white").place(relx=0.1, rely=0.8, relheight=0.1, relwidth=0.3)
    global g
    g = Entry(top1, font='Serif 10 bold')
    g.place(relx=0.5, rely=0.8, relheight=0.1, relwidth=0.4)
    
    top1.mainloop()

R1 = Button(root, text="Promiscuous Mode", command=open_Toplevel2, cursor="target", font="Serif 12 bold", bg="darkgreen", fg="white")
R1.pack(pady=20, ipadx=50)

R2 = Button(root, text="ARP Poisoning", command=open_Toplevel1, cursor="target", font="Serif 12 bold", bg="darkred", fg="white")
R2.pack(pady=10, ipadx=65)

ourMessage = '“Technology trust is a good thing, but control is a better one.”'
messageVar = Message(root, text=ourMessage, bg='lightgreen', font="Serif 12 italic", width=400)
messageVar.pack(pady=20)

root.mainloop()
