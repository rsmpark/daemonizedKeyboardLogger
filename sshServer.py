#!/usr/bin/python3

# ==============================================================================
#      File: SSH Server
#
#      Authors: Sang Min Park, Jacky Tea
#      Language: Python3
#      Libraries Used: paramiko, logzero, socket, subprocess
#
#      To compile with python3 >>> python3 contestUtil.py
#      To compile with executable >>> chmod 700 contestUtil.py
#                                 >>> ./contestUtil.py
#
#
# -----------------------------------------------------------------------------
#
#      Cookbook code utilized from the following source:
#      https://github.com/dabeaz/python-cookbook/blob/master/src/12/launching_a_daemon_process_on_unix/daemon.py
#
#      Description: SSH wrapper class for Paramiko's SSH server
#
#      Input: No command line or user input necessary.
#
#      Output: None
#
#      Algorithm: SSH functionality handled by Paramiko
#
#      Required Features Not Included:
#
#      Known Bugs:
#
# ==============================================================================


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
