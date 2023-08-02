import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, END

def receive_messages(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                print("Disconnected from server")
                break
            chat_box.config(state=tk.NORMAL)
            chat_box.insert(tk.END, message + '\n')
            chat_box.config(state=tk.DISABLED)
        except Exception as e:
            print("Error:", e)
            break

def send_message():
    message = input_box.get()
    input_box.delete(0, tk.END)
    chat_box.config(state=tk.NORMAL)
    chat_box.insert(tk.END, "You: {}\n".format(message))
    chat_box.config(state=tk.DISABLED)

    # Kirim pesan dengan mode unicast
    if target_ip_var.get():
        target_ip = target_ip_var.get()
        client_socket.send("{}: {}".format(target_ip, message).encode('utf-8'))
        return

    # Kirim pesan dengan mode multicast
    if multicast_ip_var.get():
        multicast_ip = multicast_ip_var.get()
        client_socket.send("MULTICAST {}: {}".format(multicast_ip, message).encode('utf-8'))
        return

    # Kirim pesan dengan mode broadcast
    client_socket.send("BROADCAST: {}".format(message).encode('utf-8'))

def start_client():
    server_ip = '10.217.18.147'
    server_port = 12345

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.start()

    send_button.config(state=tk.NORMAL)

window = tk.Tk()
window.title("Chatting App (Client)")
window.geometry("400x600")

chat_box = scrolledtext.ScrolledText(window, wrap=tk.WORD, state=tk.DISABLED)
chat_box.pack(expand=True, fill=tk.BOTH)

input_box = tk.Entry(window)
input_box.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

send_button = tk.Button(window, text="Send", command=send_message, state=tk.DISABLED)
send_button.pack(side=tk.RIGHT)

target_ip_var = tk.StringVar()
target_ip_entry = tk.Entry(window, textvariable=target_ip_var)
target_ip_entry.pack(side=tk.LEFT)

target_ip_label = tk.Label(window, text="Unicast IP:")
target_ip_label.pack(side=tk.LEFT)

multicast_ip_var = tk.StringVar()
multicast_ip_entry = tk.Entry(window, textvariable=multicast_ip_var)
multicast_ip_entry.pack(side=tk.LEFT)

multicast_ip_label = tk.Label(window, text="Multicast IP:")
multicast_ip_label.pack(side=tk.LEFT)

start_client_thread = threading.Thread(target=start_client)
start_client_thread.start()

window.mainloop()
