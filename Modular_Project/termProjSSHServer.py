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
        print(command)
        try:
            os.system(command)
        except Exception as err:
            print(err)
        self.event.set()
        return True
