#!/usr/bin/python3

# ==============================================================================
#      Assignment:  DPI912 Term Project
#      File: SSH Server
#
#      Authors: Sang Min Park, Jacky Tea
#      Student ID (Sang Min Park): 124218173
#      Student ID (Jacky Tea): 152078168
#      Language: Python3
#      Libraries Used: logzero, paramiko, socket
#
#      To compile with python3 >>> python3 a1SSHServer.py
#      To compile with executable >>> chmod 700 sftpClient.py
#                                 >>> sftpClient.py
#
#      Class: DPI912 NSB - Python for Programmers: Sockets and Security
#      Professor: Professor Harvey Kaduri
#      Due Date: Friday, December 6, 2019, 5:50 PM EST
#      Submitted:
#
# -----------------------------------------------------------------------------
#
#      Cookbook code utilized from the following source:
#      https://github.com/dabeaz/python-cookbook/blob/master/src/12/launching_a_daemon_process_on_unix/daemon.py
#
#      Description: A wrapper class for Paramiko's SFTP Client. Contains functions
#      for client initialization, connection and authentication.
#
#      Input: No command line or user input necessary.
#
#      Output: No output is generated here.
#
#      Algorithm: An SSH instance is created and authenticated with a username and password.
#
#      Required Features Not Included:
#
#      Known Bugs:
#
# ==============================================================================
import logzero
from logzero import logger
import socket
import paramiko

# Add logging to logfile and disable output to the terminal
logzero.logfile("/tmp/sshClient.log", maxBytes=1e6,
                backupCount=3, disableStderrLogger=True)


class sftpClient(object):
    def __init__(self, hostname, port, username, password):
        self.sftp = None
        self.transport = None
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password

    def makeSFTPConnection(self):
        try:
            logger.info("Establishing sftp connection")
            self.transport = paramiko.Transport((self.hostname, 22))
            logger.info("SFTP transport created")
            self.transport.connect(username="lab",
                                   password="lab")
            self.sftp = paramiko.SFTPClient.from_transport(self.transport)

            logger.info('SFTP Connection Established . . .')

            # handle errors
        except paramiko.AuthenticationException as authErr:
            logger.error(f'Authentication failed:{authErr}')
        except paramiko.SFTP_FAILURE as sftpErr:
            logger.error(f'SFTP connection failed:{sftpErr}')
        except socket.timeout as toutErr:
            logger.error(f'Connection timed out:{toutErr}')
        except Exception as err:
            logger.error(f'Exception has ocurred:{err}')
            self.sftp.close()
            self.transport.close()

    # upload a file via the SFTP tunnel to remote server via SFTP
    def uploadFile(self,  remotePath,  localPath):
        try:
            # connect to SFTP server
            self.makeSFTPConnection()
            self.sftp.put(localPath, remotePath)

            # Close
            if self.sftp:
                self.sftp.close()
            if self.transport:
                self.transport.close()

            # handle errors
        except Exception as err:
            logger.error(f'Exception has ocurred:{err}')
            self.sftp.close()
            self.transport.close()

    # download a file via the SSH tunnel from remote server via SFTP
    def downloadFile(self,  remotePath,  localPath):
        try:
            # connect to SSH server
            self.makeSFTPConnection()
            self.sftp.get(remotePath,  localPath)

            # Close
            if self.sftp:
                self.sftp.close()
            if self.transport:
                self.transport.close()
            # handle errors
        except Exception as err:
            logger.error(f'Exception has ocurred:{err}')
            self.sftp.close()
            self.transport.close()
