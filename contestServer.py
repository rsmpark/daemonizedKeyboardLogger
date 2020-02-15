#!/usr/bin/python3

# ==============================================================================
#      File: Non Malicious Server
#
#      Authors: Sang Min Park, Jacky Tea
#      Language: Python3
#      Libraries Used: socket
#
#      To compile with python3 >>> python3 contestServer.py
#      To compile with executable >>> chmod 700 contestServer.py
#                                 >>> ./contestServer.py
#
#
# -----------------------------------------------------------------------------
#
#      Cookbook code utilized from the following source:
#      https://github.com/dabeaz/python-cookbook/blob/master/src/12/launching_a_daemon_process_on_unix/daemon.py
#
#      Description: A simple TCP server that waits till the SSH client connects to it
#      and sends a message about the coding contest.
#
#      Input: No command line or user input necessary.
#
#      Output: Message is outputted to the screen.
#
#      Algorithm: A TCP/IP socket is created and awaits a connection before sending
#      information about the coding contest and closing.
#
#      Required Features Not Included:
#
#      Known Bugs:
#
# ==============================================================================

import socket

print("Starting the contest server....")

# initial ping
helloSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
helloSocket.bind(("127.0.0.1", 9999))
helloSocket.listen(5)
helloConnection, helloAddress = helloSocket.accept()
helloConnection.sendall(
    "Contest server up and running! Code your client to talk to us!".encode())
print(str(helloConnection.recv(1024).decode()))
helloConnection.close()
helloSocket.close()
