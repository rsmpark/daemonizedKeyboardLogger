#!/usr/bin/python3

#DPI912 Term Project

#Non Malicious Server

import socket

print("Starting the contest server....")

# initial ping
helloSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
helloSocket.bind(("127.0.0.1", 9999))
helloSocket.listen(5)
helloConnection, helloAddress = helloSocket.accept()
helloConnection.sendall("Contest server up and running! Code your client to talk to us!".encode())
print(str(helloConnection.recv(1024).decode()))

'''
# contest
print("Waiting for contest code....")
while True:
    helloConnection.sendall("Terminate this server by sending an 'X'.".encode())
    print("Your message: " + str(helloConnection.recv(1024).decode()))
    if str(helloConnection.recv(1024).decode()) == 'X':
        break
'''

helloConnection.close()
helloSocket.close()