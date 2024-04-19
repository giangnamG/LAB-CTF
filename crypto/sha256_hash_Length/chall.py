from hashlib import sha256
from os import urandom
from secret import FLAG
import base64
import json

banner = """
==================================================
||        SHA-256 Authentication Service        ||
==================================================
Usage:
[+] {"do": "register", "name": "username"} - Register a new account
[+] {"do": "login", "token": "value"} - Login with token
"""

class Service:
    def __init__(self):
        self.secret = urandom(32)
        self.hash = sha256
    
    def printBanner(self):
        print(banner)
    
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
                    message = f"Hello {userDetail[b'name'].decode()}, the flag is {FLAG}"
                else:
                    message = f"Hello {userDetail[b'name'].decode()}!"
            else:
                message = "Hello hackers!"
            
            return message

        except Exception as e:
            return e

if __name__ == "__main__":
    s = Service()
    s.printBanner()
    while True:
        try:
            inp = input(">>> ")
            inp = json.loads(inp)
            if inp["do"] == "register":
                token = s.register(inp["name"]).decode()
                print(token)
            elif inp["do"] == "login":
                message = s.login(inp["token"])
                print(message)
            else:
                print("Try again !!\n")
        except:
            break