#!/usr/bin/python3

# DPI 912 Client

import os
import argparse
import socket
import logzero
from logzero import logger

#client socket functionaility
class Client(object):
    #client socket constructor
    def __init__(self, ipAddress, socketNumber):
        try:
            self.ipAddress = ipAddress
            self.socketNumber = socketNumber
            self.clientSocket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        except Exception as err:
            raise Exception(err)
    
    #attempt to make a connection to the sercer
    def makeConnection(self):
        try:
            self.clientSocket.connect((self.ipAddress, self.socketNumber))
        except Exception as err:
            raise Exception(err)

    #attempt to send encoded data
    def sendData(self, dataBuffer):
        try:
            self.clientSocket.send(dataBuffer.encode())
        except Exception as err:
            raise Exception(err)

    #attempt to receive decoded data
    def receiveData(self, bufferSize):
        try:
            return self.clientSocket.recv(bufferSize).decode()
        except Exception as err:
            raise Exception(err)
    
    #attempt to close client socket and clean up
    def closeClient(self):
        try:
            self.clientSocket.close()
        except Exception as err:
            raise Exception(err)
            
#client function that forks off child connection from parent's main thread
def clientFork(maximumClients,  maximumConnections,  ipAddress,  socketNumber):
    #keep track of open client connections and buffer receives
    recvBuffer = ""
    socketList = []
    
    try:
        #fork off specified amount of clients
        for clientNumber in range(maximumClients):
            #fork off client to run multiple connections
            pid = os.fork()
            if pid == 0:
                for connectionNumber in range(maximumConnections):
                    #establish a connection to send lottery data, exit when finished
                    clientSocket = socket.socket(socket.AF_INET6,  socket.SOCK_STREAM)
                    clientSocket.connect((ipAddress,  socketNumber))
                    
                    #generate and send lottery data
                    clientSocket.sendall('Hello from client side!'.encode())
                    recvBuffer = clientSocket.recv(64000).decode()
                    
                    #log information about connection and requests
                    print(recvBuffer)
                    logger.info(recvBuffer)
                    
                    #track open sockets
                    socketList.append(clientSocket)
                    if(connectionNumber == maximumConnections - 1):
                        #close established connections
                        for openSocket in socketList:
                            openSocket.close()
                        os._exit(0)
                
        #wait for child process to terminate, otherwise throw an exception
        while True:
            try:
                pid,  status = os.waitpid(-1,  os.WNOHANG) 
            except OSError :
                print('Done! Data is in folder called \"a1Client.log\" in your current directory')
                logger.info('Done! Data is in folder called \"a1Client.log\" in your current directory')
                break
            
    except Exception:
        raise

#start client function
def startClient():
    #optional IPv6 address and socket number switch arguments
    #default is loopback IPv6 address ::1 and socket number 9000
    parser = argparse.ArgumentParser\
    (description = 'DPI912 Assignment - reverse shell client', \
    formatter_class = argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-ip', type=str, default="::1", \
                        help='Client IPv6 address.',  required=False)
    parser.add_argument('-socket', type=int, default=9000, \
                        help='Client socket number',  required=False)
    
    #optional client amount and connection amount to fork off
    #default is 10 clients that make 10 connections each
    parser.add_argument('-clients', type=int, default=10, \
                        help='Number of clients to fork off.',  required=False)
    parser.add_argument('-connections', type=int, default=10,  \
                        help='Number of connections per client.',  required=False)
    
     #get parameters and fork off clients to send requests
    try:
        commandLineArgs = parser.parse_args()
        ipAddress = commandLineArgs.ip
        socketNumber = commandLineArgs.socket
        maximumClients = commandLineArgs.clients
        maximumConnections = commandLineArgs.connections
        clientFork(maximumClients,  maximumConnections,  ipAddress,  socketNumber)
    except Exception as err:
        logger.error(err)
        raise 
    
#run main thread
if __name__ == "__main__":
    try:
         #log lottery data to single file
        logzero.logfile("a1lient.log", maxBytes=1e6, backupCount=3,disableStderrLogger=True)
        
        #start the client forking
        startClient()
        
        #handle errors
    except ValueError as valErr:
        print('Oh no!',  valErr)
        logger.error(valErr)
    except OSError as osErr:
        print('Oh no!',  osErr)
        logger.error(osErr)
    except SystemExit as sysExit:
        print('Oh no! Invalid command line argument types!')
        logger.error(sysExit)
    except KeyboardInterrupt:
        print('Client shutting down! (Ctrl-C)')
        logger.error('Client shutting down! (Ctrl-C)')
    except Exception as err:
        print('Oh no!',  err)
        logger.error(err)
