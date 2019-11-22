#!/usr/bin/python3

#==============================================================================
 #      Assignment:  DPI912 Term Project
 #      File: SSH Client
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

import paramiko
import socket
import os
import logzero
from logzero import logger
import threading

class SSHClient(object):
    # constructor, sets necessary parameters to establish a SSH tunnel
    def __init__(self,  hostName,  portNumber, userName,  passWord):
        self.SSHClient = None
        self.hostName = hostName
        self.portNumber = portNumber
        self.userName = userName
        self.passWord = passWord

    # make a connection to a remote SSH server
    def makeSSHConnection(self):
        try:
            logger.info("Establishing ssh connection")
            # create a client instance, auto generate a key
            # and attempt to connect to a host
            self.SSHClient = paramiko.SSHClient()
            self.SSHClient.load_system_host_keys()
            self.SSHClient.set_missing_host_key_policy(
                paramiko.WarningPolicy())

            self.SSHClient.connect(hostname=self.hostName,  port=self.portNumber,
                                   username=self.userName,  password=self.passWord)
            logger.info('SSH Connection Established . . .')

            # handle errors
        except paramiko.AuthenticationException as authErr:
            print('Authentication failed:',  authErr)
        except paramiko.SSHException as sshErr:
            print('SSH connection failed:',  sshErr)
        except socket.timeout as toutErr:
            print('Connection timed out:',  toutErr)
        except Exception as err:
            print('Exception has ocurred:',  err)
            self.SSHClient.close()

    # executes a command on a remote host
    def executeCommand(self,  command):
        try:
            # connect to SSH server
            self.makeSSHConnection()
            # run the exec_command() method to
            # execute a command remotely
            stdin,  stdout,  stderr = self.SSHClient.exec_command(command,
                                                                  timeout=10)
            print(f"command STDOUT: {str(stdout.read())}")
            if stderr:
                print(f"command STDERR: {str(stderr.read())}")
            self.SSHClient.close()
            # handle errors
        except paramiko.SSHException as sshErr:
            print('Command execution failed:',  sshErr)
            self.SSHClient.close()
        except socket.timeout as toutErr:
            print('Command timed out:',  toutErr)
            self.SSHClient.close()
        except Exception as err:
            print('Exception has ocurred:',  err)
            self.SSHClient.close()

    # upload a file via the SSH tunnel to remote server via SFTP
    def uploadFile(self,  localPath,  remotePath):
        try:
            # connect to SSH server
            self.makeSSHConnection()
            # create an SFTP tunnel
            SFTPInstance = self.SSHClient.open_sftp()
            SFTPInstance.put(localPath,  remotePath)
            # handle errors
        except Exception as err:
            print('Exception has ocurred:',  err)
            SFTPInstance.close()
            self.SSHClient.close()

    # download a file via the SSH tunnel from remote server via SFTP
    def downloadFile(self,  localPath,  remotePath):
        try:
            # connect to SSH server
            self.makeSSHConnection()
            # create an SFTP tunnel
            SFTPInstance = self.SSHClient.open_sftp()
            SFTPInstance.get(localPath,  remotePath)
            # handle errors
        except Exception as err:
            print('Exception has occurred:',  err)
            SFTPInstance.close()
            self.SSHClient.close()

    def invoke_shell(self):
        try:
            # connect to SSH server
            self.makeSSHConnection()
            channel = self.SSHClient.get_transport().open_session()
            logger.info("Calling invoke shell")
            logger.info("Invoke shell called")
            channel.sendall("hello".encode())
            logger.info("Sending message")
        except paramiko.SSHException as sshErr:
            print(f'Shell invoke failed:{sshErr}')
            self.SSHClient.close()
        except socket.timeout as toutErr:
            print('Command timed out:',  toutErr)
            self.SSHClient.close()
        except Exception as err:
            print('Exception has ocurred:',  err)
            self.SSHClient.close()

