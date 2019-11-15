#!/usr/bin/python3

import paramiko
import socket
import os


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
            print("Establishing ssh connection")
            # create a client instance, auto generate a key
            # and attempt to connect to a host
            self.SSHClient = paramiko.SSHClient()
            self.SSHClient.set_missing_host_key_policy(
                paramiko.AutoAddPolicy())

            self.SSHClient.connect(hostname=self.hostName,  port=self.portNumber,
                                   username=self.userName,  password=self.passWord)
            print('SSH Connection Established . . .')
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
            print('Exception has ocurred:',  err)
            SFTPInstance.close()
            self.SSHClient.close()


# main thread
if __name__ == '__main__':
    # pkey = os.path.realpath("tester")
    sshClient = sshClient("LAPTOP-PQ0L8NS1", 22, "smpar", "park-sang")
    # dir_path = os.path.realpath("config_file")
    # print(dir_path)

    sshClient.executeCommand('pwd')
    # sshClient.uploadFile(dir_path, "/home/smpark7/zzzz")
    # sshClient.downloadFile("/home/smpark7/zzzz",
    #                        "/home/lab/bin/py/project/destinations")
