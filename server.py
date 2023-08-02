import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, END

def receive_messages(client_socket, client_address):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                print("Client {} disconnected".format(client_address))
                break
            chat_box.config(state=tk.NORMAL)
            chat_box.insert(tk.END, "{}: {}\n".format(client_address, message))
            chat_box.config(state=tk.DISABLED)
        except Exception as e:
            print("Error:", e)
            break

def start_server():
    host = '10.217.18.147'
    port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print("Server listening on {}:{}".format(host, port))

    while True:
        client_socket, client_address = server_socket.accept()
        print("Accepted connection from:", client_address)
        clients[client_address] = client_socket

        receive_thread = threading.Thread(target=receive_messages, args=(client_socket, client_address))
        receive_thread.start()

def send_message():
    message = input_box.get()
    input_box.delete(0, tk.END)
    chat_box.config(state=tk.NORMAL)
    chat_box.insert(tk.END, "You: {}\n".format(message))
    chat_box.config(state=tk.DISABLED)

    # Kirim pesan ke klien tertentu (unicast)
    if target_ip_var.get():
        target_ip = target_ip_var.get()
        if target_ip in clients:
            clients[target_ip].send(message.encode('utf-8'))
            return

    # Kirim pesan ke semua klien (broadcast atau multicast)
    for client_socket in clients.values():
        client_socket.send(message.encode('utf-8'))

window = tk.Tk()
window.title("Chatting App (Server)")
window.geometry("400x600")

chat_box = scrolledtext.ScrolledText(window, wrap=tk.WORD, state=tk.DISABLED)
chat_box.pack(expand=True, fill=tk.BOTH)

input_box = tk.Entry(window)
input_box.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

send_button = tk.Button(window, text="Send", command=send_message)
send_button.pack(side=tk.RIGHT)

target_ip_var = tk.StringVar()
target_ip_entry = tk.Entry(window, textvariable=target_ip_var)
target_ip_entry.pack(side=tk.LEFT)

target_ip_label = tk.Label(window, text="Target IP:")
target_ip_label.pack(side=tk.LEFT)

clients = {}

server_thread = threading.Thread(target=start_server)
server_thread.start()

window.mainloop()
