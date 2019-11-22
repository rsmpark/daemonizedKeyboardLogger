#!/usr/bin/python3

# ==============================================================================
 #      Assignment:  DPI912 Term Project
 #      File: Persistent Daemon
 #
 #      Authors: Sang Min Park, Jacky Tea
 #      Student ID (Sang Min Park): 124218173
 #      Student ID (Jacky Tea): 152078168
 #      Language: Python3
 #      Libraries Used:
 #
 #      To compile:
 #
 #      Class: DPI912 NSB - Python for Programmers: Sockets and Security
 #      Professor: Professor Harvey Kaduri
 #      Due Date: Friday, December 6, 2019, 5:500 PM EST
 #      Submitted:
 #
 # -----------------------------------------------------------------------------
 #
 #      Cookbook code utilized from the following source:
 #      https://github.com/dabeaz/python-cookbook/blob/master/src/12/launching_a_daemon_process_on_unix/daemon.py
 #
 #      Description:
 #
 #      Input:
 #
 #      Output:
 #
 #      Algorithm:
 #
 #      Required Features Not Included:
 #
 #      Known Bugs:
 #
# ==============================================================================

import os
import sys
import argparse
import errno
import signal
import atexit
import logzero
import paramiko
from logzero import logger
from termProjServer import Server
from termProjSSHServer import SSHServer

#logging and key for paramiko
paramiko.util.log_to_file("termProjSSH.log")
hostKey = paramiko.RSAKey(filename="termProjRSAKey.key")

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

    #check if file exists
    if os.path.exists(pidFile):
        logger.error('Daemon already running!')
        raise RuntimeError('Daemon already running!')
    
    #first fork to detach
    try:
        if os.fork() > 0:
            logger.info('Fork 1: Detached from parent!')
            raise SystemExit('Exit Code: ' + str(0))
    except OSError:
        logger.error('First fork has failed!')
        raise RuntimeError('First fork has failed!')
    
    #set uid, gid and chdir to /tmp
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
    
    #second fork to detach as session leader
    try:
        if os.fork() > 0:
            logger.info('Fork 2: Session leadership relinquished!')
            raise SystemExit('Exit Code: ' + str(0))
    except OSError:
        logger.error('Second fork has failed!')
        raise RuntimeError('Second fork has failed!')
        
    #flush input and output buffers
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
        daemonSocket = Server(ipAddress, socketNumber, requestQueueSize)
        daemonSocket.listenForConnection()
        logger.info('Server listening on socket: ' + str(socketNumber) + ' IPv6 address: ' + ipAddress)
        logger.info('Parent PID: ' + str(os.getpid()))
    except Exception as err:
        logger.error(err)
        return
    
    #write to pid file to identify running process
    try:
        with open(pidFile,  'w') as fileHandler:
            fileHandler.write(str(os.getpid()))
    except Exception as err:
        logger.error(err)
        raise Exception(err)
        
    #remove file on exit to indicate killed process
    atexit.register(lambda: os.remove(pidFile))
    
    #sigterm handler
    def sigTermTermination(signalNo,  frame):
        logger.info('Daemon Terminated!')
        raise SystemExit(1)
    signal.signal(signal.SIGTERM,  sigTermTermination)
    
    #handle child return event, terminate the child to clean up resources
    signal.signal(signal.SIGCHLD,  processTerminator)
    
    #fork off children to handle incoming connections
    while True:
        #attempt to accept connection
        try:
            daemonSocket.acceptConnection()
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
            daemonSocket.closeServer()
            daemonSocket.sendData('Hello from daemonized server!!!!!')
            logger.info(daemonSocket.receiveData(1024))
            daemonSocket.closeConnection()
            os._exit(0)
        #parent 
        else: 
            daemonSocket.closeConnection()
            

#start daemon function
def startDaemon():
    #optional IPv6 address and socket number switch arguments
    #default is loopback IPv6 address ::1 and socket number 9000
    parser = argparse.ArgumentParser(description = 'DPI912 Term Project - non-blocking daemon.', \
                                     formatter_class = argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-ip', type=str, default="127.0.0.1", \
                        help='Daemon IPv4 address.',  required=False)
    parser.add_argument('-socket', type=int, default=9000, \
                        help='Daemon socket number.',  required=False)
    
    #optional request queue size, default is 1024
    parser.add_argument('-queue', type=int, default=1024,  \
                        help='Request queue size for the daemon.',  required=False)

    #positional arguments for start and stop
    parser.add_argument('status',  nargs='?')
    
    #semaphore file to track if daemon is currently with pid
    pidFile = '/tmp/termProjDaemon.pid'
        
    try:
        #parse arguments and start server
        commandLineArgs = parser.parse_args()
        ipAddress = commandLineArgs.ip
        socketNumber = commandLineArgs.socket
        requestQueueSize = commandLineArgs.queue
        
        #check if start and stop args were passed on the command line - cookbook
        if len(sys.argv) < 2:
            print('Incorrect Args! Usage: ./termProjDaemon.py [start | stop]')
            logger.error('Incorrect Args! Usage: ./termProjDaemon.py [start | stop]')
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

# main thread 
if __name__ == "__main__":
    # log information and errors to single file
    logzero.logfile("/home/lab/bin/py/Assignment_Term_Project/logs/termProjDaemon.log", maxBytes=1e6, backupCount=3,disableStderrLogger=True)

    # start daemon
    startDaemon()

