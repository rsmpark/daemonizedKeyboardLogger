#!/usr/bin/python3

import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('127.0.0.1',  port=2222,   username='rick',  password='jacky')
command = input('Enter a linux command to run:')
(stdin, stdout, stderr) = ssh.exec_command(command.encode())
#response = stdout.readlines()
#errormsg = stderr.read()
'''
chan = ssh.invoke_shell()
chan.send("hello".encode())
chan.close()
'''
ssh.close()
