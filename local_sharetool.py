import time
import ctypes
import socket
import webbrowser
from threading import Thread

# Encryption imports
import nacl.secret
import hashlib

# 3rd party imports
import win10toast as toast
import win32clipboard as clip

class Comm(object):
    def __init__(self, port, pword):
        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  
        self.port = port
        self.toast = toast.ToastNotifier()
        self.own_ip = socket.gethostbyname(socket.gethostname())
        pword = hashlib.md5(pword).hexdigest()
        self.box = nacl.secret.SecretBox(pword)
    
    def start_server(self):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.srv.bind(('', self.port))
        self.srv_thread = Thread(target=self._server_thread)
        self.srv_thread.setDaemon(True)
        self.srv_thread.start()
    
    def send_loop(self):
        self.send_thread = Thread(target=self._send_loop_thread)
        self.send_thread.start()
    
    def data_check(self, data):
        if data.startswith("http"):
            return True
        return False
    
    def _server_thread(self):
        while True:
            data,conn = self.srv.recvfrom(4096)
            data = self.box.decrypt(data)
            if conn[0] != self.own_ip and self.data_check(data):
                self.toast.show_toast(" ", data, duration=7, icon_path=None)
                try:
                    webbrowser.open(data)
                except:
                    print("not valid: {}".format(data))
    
    def _send_loop_thread(self, hist=""):
        while True:
            clip.OpenClipboard()
            data = clip.GetClipboardData()
            clip.CloseClipboard()
            if self.data_check(data) and hist != data:
                confirm = ctypes.windll.user32.MessageBoxA(0, str(data), "Share to network?", 0x1)
                if confirm == 1:
                    data = self.box.encrypt(data)
                    self.send_sock.sendto(data, ("255.255.255.255", self.port))
            hist = data
            time.sleep(5)

if __name__ == '__main__':
    up = Comm(7443, "netshare")
    up.start_server()
    up.send_loop()
