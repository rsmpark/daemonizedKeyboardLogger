#!/usr/bin/python3

#==============================================================================
 #      Assignment:  DPI912 Term Project
 #      File: SSH Server 
 #
 #      Authors: Sang Min Park, Jacky Tea
 #      Student ID (Sang Min Park): 124218173
 #      Student ID (Jacky Tea): 152078168
 #      Language: Python3
 #      Libraries Used:
 #
 #      To compile: 
 #
 #      Class: DPI912 NSB - Python for Programmers: Sockets and Security 
 #      Professor: Professor Harvey Kaduri
 #      Due Date: Friday, December 6, 2019, 5:500 PM EST
 #      Submitted:  
 #
 #-----------------------------------------------------------------------------
 #
 #      Cookbook code utilized from the following source:
 #      https://github.com/dabeaz/python-cookbook/blob/master/src/12/launching_a_daemon_process_on_unix/daemon.py
 #
 #      Description:
 #
 #      Input: 
 #
 #      Output: 
 #
 #      Algorithm: 
 #
 #      Required Features Not Included:  
 #
 #      Known Bugs:  
 #
#==============================================================================

import os
import socket
import sys
import threading
import paramiko
from logzero import logger

class SSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == "rick") and (password == "jacky"):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_exec_request(self, channel, command):
        # This is the command we need to parse
        try:
            commandOutput = os.system(command)
            logger.info("command output:" + str(commandOutput))
        except Exception as err:
            logger.error(err)
        self.event.set()
        logger.info(str(command.decode()) + " sucessfully executed!")
        return True


'''
# main thread
if __name__ == "__main__":
    #create server
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    serverSocket.bind(('127.0.0.1', 2222))
    serverSocket.listen(1024)

    #accept a client connection
    connectionSocket, connectionAddress = serverSocket.accept()

    #create a channel
    channel = paramiko.Transport(connectionSocket)
    channel.set_gss_host(socket.getfqdn("127.0.0.1"))
    channel.load_server_moduli()
    channel.add_server_key(paramiko.RSAKey(filename="/tmp/termProjRSAKey.key"))

    #create and start SSH server
    sshServer = SSHServer()
    channel.start_server(server=sshServer)

    #wait for event then close channel
    sshServer.event.wait(30)
    channel.close()
'''