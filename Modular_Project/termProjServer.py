#!/usr/bin/python3

#==============================================================================
 #      Assignment:  DPI912 Term Project
 #      File: TCP/IP Server
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
import logzero
from logzero import logger

# TCP/IP socket server wrapper class implementation
class Server(object):
    # Server constructor, creates a new server instance
    def __init__(self, ipAddress, portNumber, queueSize):
        try:
            self.ipAddress = ipAddress
            self.portNumber = portNumber
            self.queueSize = queueSize
            self.connectionSocket = None
            self.connectionAddress = None
            self.serverSocket = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )
            self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception as err:
            print(err)  
            logger.error(err)
        
    # method that attempts to bind and listen for incoming connections
    def listenForConnection(self):
        try:
            self.serverSocket.bind((self.ipAddress, self.portNumber))
            self.serverSocket.listen(self.queueSize)
        except Exception as err:
            print(err)
            logger.error(err)
    
    # method that accepts a connection and makes a connection socket
    def acceptConnection(self):
        try:
            self.connectionSocket, self.connectionAddress = self.serverSocket.accept()
        except Exception as err:
            print(err)
            logger.error(err)
    
    # method that sends data over a connection
    def sendData(self, dataToSend):
        try:
            self.connectionSocket.sendall(str(dataToSend).encode())
        except Exception as err:
            print(err)
            self.closeConnection()
            logger.error(err)

    # method that receives data over a connection
    def receiveData(self, bufferSize):
        try:
            return str(self.connectionSocket.recv(bufferSize).decode())
        except Exception as err:
            print(err)
            self.closeConnection()
            logger.error(err)

    # method that closes the connection socket
    def closeConnection(self):
        try:
            self.connectionSocket.close()
        except Exception as err:
            print(err)
            logger.error(err)

    # method that closes the server socket
    def closeServer(self):
        try:
            self.serverSocket.close()
        except Exception as err:
            print(err)
            logger.error(err)

