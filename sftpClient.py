#!/usr/bin/python3

import logzero
from logzero import logger
import socket
import paramiko


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
