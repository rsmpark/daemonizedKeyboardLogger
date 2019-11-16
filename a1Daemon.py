#!/usr/bin/python3

# DPI 912 Daemon

import os
import sys
import argparse
import socket
import signal
import errno
import atexit
import paramiko
import logzero
from logzero import logger

# paramiko functionality implementation
class SSHClient(object):
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

# server socket functionality
class Server(object):
    #server socket constructor
    def __init__(self, ipAddress, socketNumber, queueSize):
        try:
            self.ipAddress = ipAddress
            self.socketNumber = socketNumber
            self.queueSize = queueSize
            self.serverSocket = socket.socket(\
                socket.AF_INET6, socket.SOCK_STREAM)
            self.connectionSocket = None
            self.connectionAddress = None
            # handle errors
        except Exception as err:
            raise Exception(err)

    #attempt to make a connection and bind
    def makeConnection(self):
        try:
            self.serverSocket.setsockopt(\
                socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            self.serverSocket.bind((self.ipAddress, self.socketNumber))
            self.serverSocket.listen(self.queueSize)
            # handle errors
        except Exception as err:
            raise Exception(err)

    #attempt to accept a new connection
    def acceptConnection(self):
        try:
            self.connectionSocket, self.connectionAddress = self.serverSocket.accept()
            return (self.connectionSocket,  self.connectionAddress)
            # handle errors
        except Exception as err:
            self.serverSocket.close()
            raise Exception(err)

    #attempt to send encoded data 
    def sendData(self, dataBuffer):
        try:
            self.serverSocket.sendall(dataBuffer.encode())
            # handle errors
        except Exception as err:
            self.serverSocket.close()
            raise Exception(err)

    #attempt to receive and decode data
    def receiveData(self, bufferSize):
        try:
            return self.serverSocket.recv(bufferSize).decode()
           # handle errors
        except Exception as err:
            self.serverSocket.close()
            raise Exception(err)

    #close server socket to clean up resources
    def closeServer(self):
        try:
            self.serverSocket.close()
           # handle errors
        except Exception as err:
            raise Exception(err)

#function to get rid of zombie child processes
def processTerminator(signalNumber,  functionReference):
    #wait for child processes to complete and destroy them
    while True:
        try:
            pid,  status = os.waitpid(-1,  os.WNOHANG)
        except OSError:
            return
        #no more zombies
        if pid == 0:
            return

#persistent daemon program
def daemonExecutionLoop(ipAddress,  socketNumber,  requestQueueSize,  pidFile,  *,  \
    stdin='/dev/null',  stdout='/dev/null',  stderr='/dev/null'):

    #check if file exists -cookbook
    if os.path.exists(pidFile):
        logger.error('Daemon already running!')
        raise RuntimeError('Daemon already running!')
    
    #first fork to detach -cookbook
    try:
        if os.fork() > 0:
            logger.info('Fork 1: Detached from parent!')
            raise SystemExit('Exit Code: ' + str(0))
    except OSError:
        logger.error('First fork has failed!')
        raise RuntimeError('First fork has failed!')
    
    #set uid, gid and chdir to /tmp - cookbook
    #set session with no controlling terminal - cookbook
    #NOTE: root access required to set to 65534
    #error is thrown when not root, uncomment 
    #os.setgid(65534) and os.setuid(65534) to see
    try:
        os.chdir('/tmp')
        os.setuid(os.getuid())
        os.setgid(os.getgid())
        #os.setuid(65534)
        #os.setgid(65534)
        os.setsid()
    except Exception as err:
        logger.error(err)
        raise Exception(err)
    
    #second fork to detach as session leader - cookbook
    try:
        if os.fork() > 0:
            logger.info('Fork 2: Session leadership relinquished!')
            raise SystemExit('Exit Code: ' + str(0))
    except OSError:
        logger.error('Second fork has failed!')
        raise RuntimeError('Second fork has failed!')
        
    #flush input and output buffers - cookbook
    sys.stdout.flush()
    sys.stderr.flush()
    
    #replace file descriptors to close stdin, out, err
    try:
        with open(stdin, 'rb', 0) as fileHandler:
            os.dup2(fileHandler.fileno(), sys.stdin.fileno())
        with open(stdout, 'ab', 0) as fileHandler:
            os.dup2(fileHandler.fileno(), sys.stdout.fileno())
        with open(stderr, 'ab', 0) as fileHandler:
            os.dup2(fileHandler.fileno(), sys.stderr.fileno())
    except Exception as err:
        logger.error(err)
        raise Exception(err)
    
    #start server
    try:
        #prevent hijacking with SO_REUSEPORT parameter
        daemonSocket = socket.socket(socket.AF_INET6,  socket.SOCK_STREAM)
        daemonSocket.setsockopt(socket.SOL_SOCKET,  socket.SO_REUSEPORT,  1)
        daemonSocket.bind((ipAddress,  socketNumber))
        daemonSocket.listen(requestQueueSize)
        logger.info('Server listening on socket: ' + str(socketNumber) + ' IPv6 address: ' + ipAddress)
        logger.info('Parent PID: ' + str(os.getpid()))
    except Exception as err:
        logger.error(err)
        return
    
    #write to pid file to identify running process - cookbook
    try:
        with open(pidFile,  'w') as fileHandler:
            fileHandler.write(str(os.getpid()))
    except Exception as err:
        logger.error(err)
        raise Exception(err)
        
    #remove file on exit to indicate killed process - cookbook
    atexit.register(lambda: os.remove(pidFile))
    
    #sigterm handler - cookbook
    def sigTermTermination(signalNo,  frame):
        logger.info('Daemon Terminated!')
        raise SystemExit(1)
    signal.signal(signal.SIGTERM,  sigTermTermination)
    
    #handle child return event, terminate the child to clean up resources
    #cookbook
    signal.signal(signal.SIGCHLD,  processTerminator)
    
    #fork off children to handle incoming connections
    while True:
        #attempt to accept connection
        try:
            connectionSocket,  connectionAddress = daemonSocket.accept()
        except IOError as e:
            code,  msg = e.args
            if code == errno.EINTR:
                continue
            else:
                raise
        
        #fork off child process to do work, child doesn't listen
        pid = os.fork()
        #child
        if pid == 0: 
            daemonSocket.close()
            logger.info(connectionSocket.recv(1024).decode())
            connectionSocket.sendall('Hello from the daemon side!'.encode())
            connectionSocket.close()
            os._exit(0)
        #parent 
        else: 
            connectionSocket.close() 
            

#start daemon function
def startDaemon():
    #optional IPv6 address and socket number switch arguments
    #default is loopback IPv6 address ::1 and socket number 9000
    parser = argparse.ArgumentParser(description = 'DPI912 assignment - non-blocking daemon.', \
                                     formatter_class = argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-ip', type=str, default="::1", \
                        help='Daemon IPv6 address.',  required=False)
    parser.add_argument('-socket', type=int, default=9000, \
                        help='Daemon socket number.',  required=False)
    
    #optional request queue size, default is 1024
    parser.add_argument('-queue', type=int, default=1024,  \
                        help='Request queue size for the daemon.',  required=False)

    #positional arguments for start and stop
    parser.add_argument('status',  nargs='?')
    
    #semaphore file to track if daemon is currently with pid
    pidFile = '/tmp/a1Daemon.pid'
        
    try:
        #parse arguments and start server
        commandLineArgs = parser.parse_args()
        ipAddress = commandLineArgs.ip
        socketNumber = commandLineArgs.socket
        requestQueueSize = commandLineArgs.queue
        
        #check if start and stop args were passed on the command line - cookbook
        if len(sys.argv) < 2:
            print('Incorrect Args! Usage: ./a1Daemon.py [start | stop]')
            logger.error('Incorrect Args! Usage: ./a1Daemon.py [start | stop]')
            raise SystemExit('Exit Code: ' + str(1))
    
        #detect start command - cookbook
        if commandLineArgs.status == 'start':
            try:
                daemonExecutionLoop(ipAddress,  socketNumber,  requestQueueSize,  pidFile)
            except RuntimeError as err:
                print(err)
                logger.error(err)
            raise SystemExit('Exit Code: ' + str(1))
        #detect stop command and send signal to kill daemon - cookbook
        elif commandLineArgs.status == 'stop':
            if os.path.exists(pidFile):
                with open(pidFile) as fileHandler:
                    os.kill(int(fileHandler.read()),  signal.SIGTERM)
            else:
                print('Daemon is not currently running!')
                logger.error('Daemon is not currently running!')
                raise SystemExit('Exit Code: ' + str(1))
        #detect erroneous command - cookbook
        else:
            print('Unknown command:',  str(sys.argv[1]))
            logger.error('Unknown command:' +  str(sys.argv[1]))
            raise SystemExit('Exit Code: ' + str(1))
    except Exception:
        raise


#main thread, parse args and run server indefinitely
if __name__ == '__main__':
    try:
        #log information, errors and other output to a single file
        logzero.logfile("/tmp/a1Daemon.log", maxBytes=1e6, backupCount=3,disableStderrLogger=True)
        
        #start daemon
        startDaemon()

        #handle errors
    except ValueError as valErr:
        logger.error(valErr)
    except SystemExit as sysExit:
        logger.error(sysExit)
    except KeyboardInterrupt:
        logger.error('Ctrl-C Shutdown!')
    except Exception as err:
        logger.error(err)


