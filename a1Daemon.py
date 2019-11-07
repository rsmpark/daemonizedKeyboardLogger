#!/usr/bin/python3

# DPI 912 Daemon

import socket
import logzero
from logzero import logger
import os
import signal
import sys
import atexit


class Server(object):
    def __init__(self, ipAddress, socketNumber, queueSize=1024):
        try:
            self.ipAddress = ipAddress
            self.socketNumber = socketNumber
            self.queueSize = queueSize
            self.serverSocket = socket.socket(
                socket.AF_INET6, socket.SOCK_STREAM)
            self.connectionSocket = None
            self.connectionAddress = None
        except Exception as err:
            raise Exception(err)

    def makeConnection(self):
        try:
            self.serverSocket.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            self.serverSocket.bind((self.ipAddress, self.socketNumber))
            self.serverSocket.listen(self.queueSize)
        except Exception as err:
            raise Exception(err)

    def acceptConnection(self):
        try:
            self.connectionSocket, self.connectionAddress = self.serverSocket.accept()
            return (self.connectionSocket, self.connectionAddress)
        except Exception as err:
            raise Exception(err)

    def sendData(self, dataBuffer):
        try:
            self.serverSocket.sendall(dataBuffer).encode()
        except Exception as err:
            raise Exception(err)

    def receiveData(self, bufferSize):
        try:
            return self.serverSocket.recv(bufferSize).decode()
        except Exception as err:
            raise Exception(err)

    def closeServer(self):
        try:
            self.serverSocket.close()
        except Exception as err:
            raise Exception(err)


class DaemonServer(Server):
    def __init__(self, pidfile, ipAddress, socketNumber, queueSize=1024):
        self.pidfile = pidfile
        Server.__init__(self, ipAddress, socket, queueSize)

    def daemonize(self, pidfile, *, stdin='/dev/null',
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
        is later used to kill the daemon. """

        # If pidfile exists, there is a server program that is currently running
        if os.path.exists(self.pidfile):
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

        # Write the PID file
        with open(self.pidfile, 'w') as f:
            print(fork2DaemonPID, file=f)

        logger.info(f"fork#2 successful pid[{fork2DaemonPID}]")

        # Arrange to have the PID file removed on exit/signal
        atexit.register(lambda: os.remove(pidfile))

        # Signal handler for termination (required)
        def sigterm_handler(signo, frame):
            raise SystemExit(1)

        signal.signal(signal.SIGTERM, sigterm_handler)


if __name__ == '__main__':
    try:
        server = Server('::1', 9000, 1024)
        server.makeConnection()
        connectionSocket, connectionAddress = server.acceptConnection()
        connectionSocket.send('Hello from Server'.encode())
        print(connectionSocket.recv(1024).decode())
        connectionSocket.close()
        server.closeServer()
    except Exception as err:
        print(err)
