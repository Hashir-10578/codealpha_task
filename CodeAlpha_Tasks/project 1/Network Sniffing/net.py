import threading
import tkinter as tk
from tkinter import ttk
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

sniffing = False
target_ip = ""

IGNORE_PORTS = {53, 1900, 5355, 445, 137, 138}

# ---------------- Packet Handler ---------------- #
def packet_callback(packet):
    global target_ip

    if not sniffing:
        return

    if IP in packet:
        src_ip = packet[IP].src
        
        dst_ip = packet[IP].dst

        protocol = "OTHER"
        src_port = "-"
        dst_port = "-"
        flags = "-"
        length = len(packet)
        payload_size = len(packet[IP].payload)

        # Check if packet matches target IP
        match = "NO"
        tag_type = "NORMAL"

        if target_ip and target_ip in (src_ip, dst_ip):
            match = "YES"
            tag_type = "MATCH"

        if TCP in packet:
            if packet[TCP].sport in IGNORE_PORTS or packet[TCP].dport in IGNORE_PORTS:
                return
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags

        elif UDP in packet:
            if packet[UDP].sport in IGNORE_PORTS or packet[UDP].dport in IGNORE_PORTS:
                return
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"

        tree.insert("", "end",
                    values=(src_ip, dst_ip, protocol,
                            src_port, dst_port,
                            length, payload_size, flags, match),
                    tags=(protocol, tag_type))


# ---------------- Sniff Thread ---------------- #
def start_sniffing():
    global sniffing, target_ip
    target_ip = ip_entry.get().strip()
    sniffing = True
    status_label.config(text="Status: Sniffing All Traffic", fg="#00ff00")
    sniff(prn=packet_callback, store=False)

def stop_sniffing():
    global sniffing
    sniffing = False
    status_label.config(text="Status: Stopped", fg="red")

def start_thread():
    thread = threading.Thread(target=start_sniffing, daemon=True)
    thread.start()


# ---------------- GUI ---------------- #
root = tk.Tk()
root.title("Advanced Network Sniffer - Highlight Specific IP")
root.geometry("1200x650")
root.configure(bg="#1e1e1e")

style = ttk.Style()
style.theme_use("default")

style.configure("Treeview",
                background="#2b2b2b",
                foreground="white",
                rowheight=25,
                fieldbackground="#2b2b2b")

style.configure("Treeview.Heading",
                background="#1e1e1e",
                foreground="white")

# Title
title = tk.Label(root,
                 text="Network Sniffer (Highlight Specific IP)",
                 font=("Arial", 16, "bold"),
                 bg="#1e1e1e",
                 fg="white")
title.pack(pady=10)

# IP Input
ip_frame = tk.Frame(root, bg="#1e1e1e")
ip_frame.pack(pady=5)

ip_label = tk.Label(ip_frame,
                    text="Highlight IP:",
                    bg="#1e1e1e",
                    fg="cyan")
ip_label.pack(side="left", padx=5)

ip_entry = tk.Entry(ip_frame,
                    width=25,
                    bg="#2b2b2b",
                    fg="white",
                    insertbackground="white")
ip_entry.pack(side="left", padx=5)

# Status
status_label = tk.Label(root,
                        text="Status: Stopped",
                        font=("Arial", 12),
                        bg="#1e1e1e",
                        fg="red")
status_label.pack(pady=5)

# Table
frame = tk.Frame(root, bg="#1e1e1e")
frame.pack(fill="both", expand=True, padx=10, pady=10)

columns = ("Source IP", "Destination IP", "Protocol",
           "Source Port", "Destination Port",
           "Packet Length", "Payload Size",
           "Flags", "Match")

tree = ttk.Treeview(frame, columns=columns, show="headings")

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=130)

tree.pack(fill="both", expand=True)

# Protocol Colors
tree.tag_configure("TCP", foreground="#00ffff")
tree.tag_configure("UDP", foreground="#ffff00")
tree.tag_configure("ICMP", foreground="#ff8800")
tree.tag_configure("OTHER", foreground="#ffffff")

# Highlighted IP rows
tree.tag_configure("MATCH", background="#004d00")   # dark green
tree.tag_configure("NORMAL", background="#2b2b2b")

# Buttons
button_frame = tk.Frame(root, bg="#1e1e1e")
button_frame.pack(pady=10)

start_btn = tk.Button(button_frame,
                      text="Start Sniffing",
                      width=20,
                      bg="#333333",
                      fg="white",
                      command=start_thread)
start_btn.grid(row=0, column=0, padx=10)

stop_btn = tk.Button(button_frame,
                     text="Stop Sniffing",
                     width=20,
                     bg="#333333",
                     fg="white",
                     command=stop_sniffing)
stop_btn.grid(row=0, column=1, padx=10)

clear_btn = tk.Button(button_frame,
                      text="Clear Table",
                      width=20,
                      bg="#333333",
                      fg="white",
                      command=lambda: tree.delete(*tree.get_children()))
clear_btn.grid(row=0, column=2, padx=10)

root.mainloop()
