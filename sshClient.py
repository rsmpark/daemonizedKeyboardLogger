#!/usr/bin/python3

#==============================================================================
 #      Assignment:  DPI912 Term Project
 #      File: SSH Client
 #
 #      Authors: Sang Min Park, Jacky Tea
 #      Student ID (Sang Min Park): 124218173
 #      Student ID (Jacky Tea): 152078168
 #      Language: Python3
 #      Libraries Used: paramiko, logzero, socket, subprocess
 #
 #      To compile with python3 >>> python3 contestUtil.py 
 #      To compile with executable >>> chmod 700 contestUtil.py
 #                                 >>> ./contestUtil.py
 #
 #      Class: DPI912 NSB - Python for Programmers: Sockets and Security 
 #      Professor: Professor Harvey Kaduri
 #      Due Date: Friday, December 6, 2019, 5:50 PM EST
 #      Submitted:  
 #
 #-----------------------------------------------------------------------------
 #
 #      Cookbook code utilized from the following source:
 #      https://github.com/dabeaz/python-cookbook/blob/master/src/12/launching_a_daemon_process_on_unix/daemon.py
 #
 #      Description: SSH wrapper class for Paramiko's SSH client
 #
 #      Input: No command line or user input necessary.
 #
 #      Output: Logging about info and errors to 'sshClient.log'
 #
 #      Algorithm: SSH functionality handled by Paramiko
 #
 #      Required Features Not Included:  
 #
 #      Known Bugs:  
 # 
 #==============================================================================

import logzero
from logzero import logger
import paramiko
import subprocess
import socket

# Add logging to logfile and disable output to the terminal
logzero.logfile("sshClient.log", maxBytes=1e6,
                backupCount=3, disableStderrLogger=True)


class sshClient(object):
    # constructor, sets necessary parameters to establish a SSH tunnel
    def __init__(self,  hostname,  port, username,  password):
        self.sshConnection = None
        self.channel = None
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.command = ""

    # make a connection to a remote SSH server
    def makeSSHConnection(self):
        try:
            logger.info("Establishing ssh connection")
            # create a client instance, auto generate a key
            # and attempt to connect to a host
            self.sshConnection = paramiko.SSHClient()
            self.sshConnection.load_system_host_keys()
            self.sshConnection.set_missing_host_key_policy(
                paramiko.WarningPolicy())

            self.sshConnection.connect(hostname=self.hostname,  port=self.port,
                                       username=self.username,  password=self.password)
            self.channel = self.sshConnection.get_transport().open_session()
            logger.info('SSH Connection Established . . .')

            # handle errors
        except paramiko.AuthenticationException as authErr:
            logger.error(f'Authentication failed:{authErr}')
        except paramiko.SSHException as sshErr:
            logger.error(f'SSH connection failed:{sshErr}')
        except socket.timeout as toutErr:
            logger.error(f'Connection timed out:{toutErr}')
        except Exception as err:
            logger.error(f'Exception has ocurred:{err}')
            self.sshConnection.close()

    def send(self, data):
        try:
            logger.info("[+]    sshSend starting")

            self.channel.sendall(data.encode())

            logger.info("[-]    sshSend ending")
        except paramiko.SSHException as sshErr:
            logger.error(f'Shell invoke failed:{sshErr}')
            self.sshConnection.close()
        except socket.timeout as toutErr:
            logger.error(f'Connection timed out:{toutErr}')
            self.sshConnection.close()
        except Exception as err:
            logger.error(f'Exception has ocurred:{err}')
            self.sshConnection.close()

    def receive(self):
        try:
            logger.info("[+]    sshReceive starting")

            dataPacket = self.channel.recv(1028).decode()
            logger.info(f"Received message {dataPacket}")

            logger.info("[-]    sshReceive ending")

            return dataPacket
        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess error: {e.output.decode()}")
        except paramiko.SSHException as sshErr:
            logger.error(f'Shell invoke failed:{sshErr}')
            self.sshConnection.close()
        except socket.timeout as toutErr:
            logger.error(f'Connection timed out:{toutErr}')
            self.sshConnection.close()
        except Exception as err:
            logger.error(f'Exception has ocurred:{err}')
            self.sshConnection.close()

    def invokeShell(self):
        try:
            logger.info("[+]    invoke_shell starting")

            receivedCommand = self.channel.recv(1024).decode()
            logger.info(f"Invoke code: {receivedCommand}")
            p = subprocess.Popen(receivedCommand, shell=True,
                                 stdout=subprocess.PIPE)

            self.channel.sendall(receivedCommand.encode())

            logger.info("[-]    invoke_shell ending")
        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess error: {e.output.decode()}")
        except paramiko.SSHException as sshErr:
            logger.error(f'Shell invoke failed:{sshErr}')
            self.sshConnection.close()
        except socket.timeout as toutErr:
            logger.error(f'Connection timed out:{toutErr}')
            self.sshConnection.close()
        except Exception as err:
            logger.error(f'Exception has ocurred:{err}')
            self.sshConnection.close()
