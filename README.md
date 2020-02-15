# Daemonized Keyboard Logger
### Demo
    
    
For deployment instructions, please refer to the videos or text below.

### How To Execute

Step 0: Make sure you are running as root on your machine.

Step 1: Make sure all source code and key files are in your current directory.
The following 9 files are part of the project:
- codingContest.py
- contestServer.py
- contestUtil.py
- keyLogger.py
- sftpClient.py
- sshClient.py
- sshServer.py
- sshDaemon.py
- test_rsa.key



Step 2: Open up a terminal, turn the following files into executables.

`>>>` chmod 700 codingContest.py

`>>>` chmod 700 contestServer.py

`>>>` chmod 700 sshDaemon.py

Note: If you do not wish to turn the files in to executables you can simply
run with them with the command >>> python3 sshDaemon.py -status start



Step 3: In your current terminal (which simulates the attacker side), start
the sshDaemon.py and contestServer.py files:

`>>>` ./sshDaemon.py -status start

`>>>` ./contestServer.py

Note: The contestServer.py file runs a TCP/IP connection on port 9999 and on IPv4 address 
of '127.0.0.1'.

Note: The sshDaemon.py has a TCP/IP connection on port 9000 and on IPv4 address 
of '127.0.0.1'. It also starts SSH on port 22 of localhost, requiring root access.

Note: The time interval to key log can be changed with a -sleep switch.
This is the time the daemon sleeps before terminating the key logger.
Default value is 24.

example. `>>>` ./sshDaemon.py -status start -sleep 30



Step 4: Now that the server is waiting for a client connection, open up a 
second terminal (which simulates the targeted user side) and start the client:

`>>>` ./codingContest.py

Note: The codingContest.py file runs a TCP/IP connection on port 9999 and on IPv4 address 
of '127.0.0.1'. There is a second TCP/IP connection on port 9000 and an SSH tunnel on 22, 
all on localhost and requiring root access.


`Step 5: The codingContest.py file prints some information about the contest to the 
screen and stop execution. At this point just type anything you want in the terminal,
or anywhere else in your machine such as a text editor or in your browser. After about
30 seconds or so, a file called 'clientKeyLogs.log' should appear in the directory you
executed all the code from (your current directory). This file will contain character
by character data about all keystrokes you pressed within a certain interval of time.`

  
