#!/usr/bin/python3

# DPI 912 Client

import socket

class Client(object):
    def __init__(self, ipAddress, socketNumber):
        try:
            self.ipAddress = ipAddress
            self.socketNumber = socketNumber
            self.clientSocket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        except Exception as err:
            raise Exception(err)
    
    def makeConnection(self):
        try:
            self.clientSocket.connect((self.ipAddress, self.socketNumber))
        except Exception as err:
            raise Exception(err)

    def sendData(self, dataBuffer):
        try:
            self.clientSocket.send(dataBuffer.encode())
        except Exception as err:
            raise Exception(err)

    def receiveData(self, bufferSize):
        try:
            return self.clientSocket.recv(bufferSize).decode()
        except Exception as err:
            raise Exception(err)
    
    def closeClient(self):
        try:
            self.clientSocket.close()
        except Exception as err:
            raise Exception(err)

if __name__ == '__main__':
    try:
        client = Client('::1', 9000)
        client.makeConnection()
        client.sendData('Hello from Client')
        print(client.receiveData(1024))
        client.closeClient()
    except Exception as err:
        print(err)
