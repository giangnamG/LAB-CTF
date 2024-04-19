import socket, threading
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime, inverse
import random, time

class RSA:
    def __init__(self):
        random.seed(int(time.time()))
        self.p = self.getPrime(random.getrandbits(512))
        self.q = self.getPrime(random.getrandbits(512))
        assert isPrime(self.p) == True and isPrime(self.q) == True
        self.n = self.p * self.q
        self.phi = (self.p-1)*(self.q-1)
        self.e = 65537
        self.d = inverse(self.e, self.phi)
        self.flag = "ISPCTF{The_Correct_Answer_28376}"
        self.enc_flag = hex(pow(bytes_to_long(self.flag.encode('utf-8')), self.e, self.n))
    
    def getPrime(self, num):
        if num % 2 == 0:
            num += 1
        while not isPrime(num):
            num += 2
        return num
    def title(self):
        return '''
        ----------------------------------------------------------------
        |     WELCOME TO MY RSA SERVICE ENCRYPT AND DECRYPT FOR FREE   | 
        ----------------------------------------------------------------                                                 
        |        1. Give me a message and then receive a encryption    |
        |        2. Give me a decryption and then receive a message    |
        |        3. Receive encrypted the flag as a gift               |
        |        4. Give me the key (d) to get the flag as rewards     |
        |--------------------------------------------------------------|
        '''
    def encrypt(self, mess):
        # print("d: %s" %hex(self.d))
        try:
            return hex(pow(bytes_to_long(mess.encode('utf-8')), self.e,self.p*self.q))
        except Exception as e:
            return 'Some thing went wrong'
    def decrypt(self, isGetFlag, enc, key):
        try:
            if isGetFlag:
                key = int(key, 16)
            else:
                key = self.d
            mess = long_to_bytes(pow(int(enc, 16), key, self.n)).decode('utf-8')
            return mess
        except Exception as e:
            return "Invalid Key !!!\n"
        
class User:
    def __init__(self, conn, addr):
        self.conn, self.addr = conn, addr

    def session(self):
        rsa = RSA()
        self.PushStream(rsa.title())
        while True:
            try:
                try:
                    self.PushStream("Your choice: ")
                    choice = int(self.GetStream())
                    if choice == 1:
                        self.PushStream("What would you like to encrypt? Type here: ")
                        mess = self.GetStream()
                        enc = rsa.encrypt(mess)
                        if enc == 'Some thing went wrong':
                            self.PushStream("Some thing went wrong")
                        else:
                            self.PushStream((f"Here your cipher: {enc}\n"))
                    elif choice == 2:
                        self.PushStream("What would you like to decrypt? Type here: ")
                        enc = self.GetStream()
                        data = rsa.decrypt(isGetFlag=False, enc=enc, key=None)
                        if data == "Invalid Key":
                            self.PushStream(f"Sorry!! Your cipher not found in my service\n")
                        else:
                            self.PushStream(f"Here your data: {data}\n")
                    elif choice == 3:
                        self.PushStream(f"Here your encryption of the flag: {rsa.enc_flag}\n")
                    elif choice == 4:
                        self.PushStream("What is your key? Type here: ")
                        key = self.GetStream()
                        data = rsa.decrypt(isGetFlag=True, enc=rsa.enc_flag, key=key)
                        if data == rsa.flag:
                            self.PushStream(f"Congratulation !! Please submit your flag and receive your reward !! {rsa.flag}\n")
                        else:
                            self.PushStream(data)
                    else:
                        self.PushStream(rsa.title())
                except Exception as e:
                    self.PushStream("Something went wrong\n")
                
            except socket.error as e:
                print(f"Error receiving/sending data from {self.addr}: {e}\n")
                self.conn.close()
                break
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