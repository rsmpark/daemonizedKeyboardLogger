#!/usr/bin/python3

import base64
from binascii import hexlify
import os
import socket
import sys
import threading
import traceback

import paramiko
from paramiko.py3compat import b, u, decodebytes

host_key = paramiko.RSAKey(filename="test_rsa.key")


class SSHServer(paramiko.ServerInterface):

    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == "rick") and (password == "jacky"):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED
