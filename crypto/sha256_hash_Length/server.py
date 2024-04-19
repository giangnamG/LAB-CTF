import threading, socket
import base64, json
from os import urandom
from hashlib import sha256

class User:
    def __init__(self, conn, addr):
        self.conn, self.addr = conn, addr
        self.secret = urandom(32)
        self.hash = sha256
        self.FLAG = 'ISPCTF{Ohno$IL0v3Y0u$0Much}'
    def banner(self):
        return """
        ==================================================
        ||        SHA-256 Authentication Service        ||
        ==================================================
Usage:
    [+] {"do": "register", "name": "username"} - Register a new account
    [+] {"do": "login", "token": "value"} - Login with token
    """
    def session(self):
        self.PushStream(self.banner()+"\n")
        while True:
            try:
                self.PushStream(">>> ")
                inp = self.GetStream()
                inp = json.loads(inp)
                if inp["do"] == "register":
                    token = self.register(inp["name"]).decode()
                    self.PushStream(token+"\n")
                elif inp["do"] == "login":
                    message = self.login(inp["token"])
                    self.PushStream(message+"\n")
                else:
                    self.PushStream("Try again !!\n")
            except Exception as e:
                self.PushStream("{self.addr} disconnected!\n")
                print(f"Error receiving/sending data from {self.addr}: {e}\n")
                self.conn.close()
                break
    def register(self, username, isAdmin=False):
        data = f"name={username}&admin={isAdmin}".encode()
        token = self.hash(self.secret + data).digest()
        return base64.b64encode(data) + b'.' + base64.b64encode(token)

    def login(self, token):
        try:
            data, token = token.split(".")
            data = base64.b64decode(data)
            token = base64.b64decode(token)
            if self.hash(self.secret + data).digest() == token:
                data = data.split(b"&")
                userDetail = {}
                for d in data:
                    tmp = d.split(b"=")
                    userDetail[tmp[0]] = tmp[1]

                if userDetail[b"admin"] == b"True":
                    message = f"Hello {userDetail[b'name'].decode()}, the flag is {self.FLAG}"
                else:
                    message = f"Hello {userDetail[b'name'].decode()}!"
            else:
                message = "Hello hackers!"
            
            return message

        except Exception as e:
            return e
    def GetStream(self):
        return self.conn.recv(1024).decode('utf-8').strip()
    def PushStream(self, mess):
        self.conn.sendall(bytes(mess,'utf-8'))
        

class App:
    
    def __init__(self, host, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((host, port))
        self.socket.listen()
        print(f"server is on {host}:{port}")
    
    def listen(self):
        while True:
            try:
                conn, addr = self.socket.accept()
                new_user = User(conn, addr)
                threading.Thread(target=new_user.session).start()
                print(f"{addr} connected")
            except Exception as e:
                pass
if __name__ == "__main__":
    server = App('0.0.0.0',7777)
    server.listen()
    