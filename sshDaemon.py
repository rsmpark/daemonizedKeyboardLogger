#!/usr/bin/python3

# ==============================================================================
#   Assignment:  MILESTONE 3
#
#       Author:  Sang Min Park
#     Language:  Python | Libraries: socket, json, os, errno, argparse,
#                                    lotteryGenerator, signal, sys, atexit,
#                                    logzero
#   To Compile:  N/A
#
#        Class:  DPI912
#    Professor:  Harvey Kaduri
#     Due Date:  Sunday, November 03, 2019
#    Submitted:  Sunday, November 03, 2019
#
# -----------------------------------------------------------------------------
#
#  Description:  Multi-processing program creates a well-behaving daemon process that listens to
#                   incoming client connection. Once connection has been successfully
#                   accepted, child process is forked off to handle their lottery ticket requests.
#                   The daemon process is killed when the use runs the program
#                   with "-status stop" command.
#
#
#
#        Input:  Program takes command line arguments for port number, IPv6 address,
#                   and status command.
#
#       Output:  The program will write all server logs into a logfile located
#                   in the /tmp directory. The file name will be the name of the client
#                   and the pid for its file extension.
#
#    Algorithm:  The program will create daemon with a non-blocking listening socket for the server.
#                   Pidfile is created and stores pid of the daemon process. It is later access by
#                   the program to kill the daemon process when "-status stop" command is issued.
#                   Once the socket accepts a connection, a child process will be forked
#                   to handle all requests sent by the client. Before handling the requests,
#                   the child processes need to close their listening socket.
#                   The program uses lotteryGenerator script file to provide
#                   appropriate lottery tickets requested by the client.
#                   The parent process will go on to close the connection socket and loop back
#                   to listen to other incoming connections.
#
#   Required Features Not Included:  N/A
#
#   Known Bugs:  N/A
#
# ==============================================================================

import os
import errno
import signal
import socket
import json
import a1SSHServer
import argparse
import sys
import atexit
import logzero
import paramiko
from logzero import logger

# Maximum queue size for the server to handle incoming client
requestQueueSize = 1024
# Size of the header that will be attached to all data packets
headersize = 10
# Delimiter that is used to append in between data packets
delimiter = "&&"
# Pathway of pidfile that will contain the pid of double-forked daemon
pidfile = "/tmp/daemonServer.pid"

host_key = paramiko.RSAKey(filename="test_rsa.key")


def grimReaper(signum,  frame):
    # TODO: remove function and try running the program without it
    """Harvests child processes that have sent a signal. Ensures no zombies"""
    while True:
        try:
            # Wait for any child process, do not block and return EWOULDBLOCK error
            pid,  status = os.waitpid(-1,  os.WNOHANG)
        except OSError:
            return
        # To ensure no zombies
        if pid == 0:
            return
    print('Child {pid} terminated with status {status}'.format(
        pid=pid,  status=status))


def parseCmdArgument():
    """Creating a parser to parse the command line arguments"""
    parser = argparse.ArgumentParser(description='CLI inputs to create server socket',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,)

    # argument for the type of lottery wanted by the user
    parser.add_argument('-port',
                        help="""port number for socket""",
                        type=int, default=9000
                        )
    # argument for the amount of lottery tickets
    parser.add_argument('-ip', type=str,
                        help="IPv6 address (e.g. ::1)",
                        default="::1")

    # argument for execution status of the server
    parser.add_argument('-status', type=str,
                        help="start (execute server program) | stop (kill server)",
                        required=True)
    # return the parsed command line arguments
    return parser.parse_args()


def generateAddress(commandArgs):
    """Generate address for the server socket"""
    # Return a tuple of IPv6 address and a port number to be used
    # to create a server socket
    return commandArgs.ip, commandArgs.port


def createSocket():
    """Creating a server socket"""
    try:
        serverSocket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        return serverSocket
    except socket.error as e:
        logger.error(f"Error creating a socket: {e}")
        exit()


def bindSocket(serverSocket, address):
    """Binding socket and listening for oncoming connection"""
    try:
        # Binding socket to address
        serverSocket.bind(address)
        # Listening to oncoming connection
        serverSocket.listen(requestQueueSize)
    except socket.error as e:
        logger.error(f"Error binding socket: {e}")
        serverSocket.close()
        exit()


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

    # Write the PID file
    with open(pidfile, 'w') as f:
        print(fork2DaemonPID, file=f)

    logger.info(f"fork#2 successful pid[{fork2DaemonPID}]")

    # Arrange to have the PID file removed on exit/signal
    atexit.register(lambda: os.remove(pidfile))

    # Signal handler for termination (required)
    def sigterm_handler(signo, frame):
        raise SystemExit(1)

    signal.signal(signal.SIGTERM, sigterm_handler)


def serverForever(commandArgs):
    """Main function that will execute forever until os kills the process.
    Parent process will listen to all possible incoming clients.
    Once connection has been established parent will fork a child per connection.
    Parent will close the connection socket and loop back to the beginning.
    Child processes will always close the listening socket and handle request from client."""

    # Generate address to be used for the server socket
    address = generateAddress(commandArgs)
    # Create listening server socket
    listeningServerSocket = createSocket()
    # Securing possible socket hijacking
    listeningServerSocket.setsockopt(
        socket.SOL_SOCKET,  socket.SO_REUSEPORT,  1)

    # Bind server socket to listen for oncoming connection
    bindSocket(listeningServerSocket, address)

    logger.info('Server HTTP on port {address} ...'.format(address=address))

    # event handler - when child dies, returns the signal SIGCHILD, grim_reaper then cleans it up to prevent zombies
    signal.signal(signal.SIGCHLD,  grimReaper)

    while True:
        try:
            logger.info("Waiting for connection")
            # Accept incoming connection from client
            connectionServerSocket,  clientAddress = listeningServerSocket.accept()
        except IOError as e:
            errorCode,  errorMssg = e.args
            # restart 'accept' if it was interrupted
            if errorCode == errno.EINTR:
                continue
            else:
                raise

        pid = os.fork()
        # Separate child from its parent
        if pid == 0:
            logger.info(
                f"fork#3 successful [{os.getpid()}]: handling client{clientAddress} requests")
            # Only child daemon will execute from this point on
            # Closing listening socket for childeren
            listeningServerSocket.close()

            # Creating SSH Server
            logger.info("Creating SSH Server")
            sshSocket = paramiko.Transport(connectionServerSocket)

            sshSocket.add_server_key(host_key)
            sshServer = a1SSHServer.SSHServer()

            try:
                logger.info("Starting SSH Server")
                sshSocket.start_server(server=sshServer)
            except paramiko.SSHException:
                print("*** SSH negotiation failed.")
                sys.exit(1)

            logger.info("Connecting SSH Server")
            sshChannel = sshSocket.accept(1)
            if sshChannel is None:
                print("*** No channel.")
                sys.exit(1)
            logger.info("Authenticated!")

            # Subprocess executing command
            logger.info("Waiting for SSH message.")

            # command chaine
            sshChannel.send(
                "touch GET_HACKED_HAHA.py | echo \"#!/usr/bin/python3\nprint('Hey, you just got hacked!')\" > GET_HACKED_HAHA.py | python3 GET_HACKED_HAHA.py")
            RXmessage = sshChannel.recv(1024).decode()

            logger.info("Received SSH message.")
            logger.info(RXmessage)

            sshChannel.close()

            # Once task is completed close connection socket
            connectionServerSocket.close()
            # Children  exits here
            os._exit(0)
        else:
            # Parent resumes code here after forking
            # Close parent's copy of connection server and loop over to continue to listen
            # for incoming connection
            connectionServerSocket.close()


if __name__ == '__main__':
    # Parse command line arguments
    commandArgs = parseCmdArgument()

    # Add logging to logfile and disable output to the terminal
    logzero.logfile("/home/lab/bin/py/project/sshDaemon.log", maxBytes=1e6,
                    backupCount=3, disableStderrLogger=True)

    # Start server process
    if commandArgs.status == "start":
        logger.info("Server process starting...")
        try:
            # Start daemonizing process
            daemonize(pidfile, stdout='/tmp/daemonServer.pid',
                      stderr='/tmp/daemonServer.pid')
            # Run server process to handle client connections
            serverForever(commandArgs)
        except RuntimeError as e:
            print(e, file=sys.stderr)
            logger.error(e)
            raise SystemExit(1)
    # Kill server process
    elif commandArgs.status == "stop":
        # Kill the process id that is located in the pidfile
        if os.path.exists(pidfile):
            logger.info("Server process killed...\n")
            with open(pidfile) as file:
                os.kill(int(file.readline().rstrip()), signal.SIGTERM)
        else:
            print("Expected server pidfile not found", file=sys.stderr)
            logger.error("Expected server pidfile not found")
            raise SystemExit(1)
    else:
        print("Wrong status command", file=sys.stderr)
        logger.error("Wrong status command")
        raise SystemExit(1)
