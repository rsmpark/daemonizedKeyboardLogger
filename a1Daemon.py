#!/usr/bin/python3

# DPI 912 Daemon

import socket


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
