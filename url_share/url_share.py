import time
import ctypes
import socket
import webbrowser
from threading import Thread
import hashlib

# 3rd party imports
import nacl.secret
import win10toast as toast

# Clipboard globals
CF_TEXT = 1
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32
kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
kernel32.GlobalLock.restype = ctypes.c_void_p
kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
user32.GetClipboardData.restype = ctypes.c_void_p

def get_clipboard_text():
    user32.OpenClipboard(0)
    try:
        if user32.IsClipboardFormatAvailable(CF_TEXT):
            data = user32.GetClipboardData(CF_TEXT)
            data_locked = kernel32.GlobalLock(data)
            text = ctypes.c_char_p(data_locked)
            value = text.value
            kernel32.GlobalUnlock(data_locked)
            return value
    finally:
        user32.CloseClipboard()

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
            data = get_clipboard_text()
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
