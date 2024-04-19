import threading, socket
from Crypto.Util.number import bytes_to_long, getPrime, inverse

class RSA:
    def __init__(self):
        p, q = getPrime(512), getPrime(512)
        self.n = p*q
        self.e = 65537
        self.d = inverse(self.e,(p-1)*(q-1))
        
    def _encrypt(self,message):
        try:
            return hex(pow(bytes_to_long(message.encode('utf-8')),self.e,self.n)), self.e, self.n
        except Exception:
            return 'Error'
    def _decrypt(self,cipher):
        try:
            cipher = int(cipher, 16)
            return pow(cipher, self.d, self.n)%2
        except Exception:
            return 'Error'
        
class User:
    def __init__(self, conn, addr):
        self.conn,self.addr = conn, addr
        self.flag = 'ISPCTF{0r4c4lc4lc4lc4l_LSB_273449234}congratulation'
    def title(self):
        return '''
    ----------------------------------------------------------------
    |            WELCOME TO MY RSA SERVICE ENCRYPTION ORACLE       | 
    ----------------------------------------------------------------                                                 
    |        1. Get Flag                                           |
    |        2. Encryption                                         |
    |        3. Decryption                                         |
    |--------------------------------------------------------------|
    '''
    def session(self):
        self.pushStream(self.title()+"\n")
        rsa = RSA()
        while True:
            try:
                self.pushStream("Your choice: ")
                choice = self.getStream()
                if choice == '1':
                    cipher, e, n = rsa._encrypt(self.flag)
                    self.pushStream(f"(cipher,e,n):({cipher},{e},{n})\n")
                elif choice == '2':
                    self.pushStream('What your message: ')
                    mess = self.getStream()
                    cipher, e, n = rsa._encrypt(mess)
                    self.pushStream(f"(cipher,e,n):({cipher},{e},{n})\n")
                elif choice == '3':
                    self.pushStream('What your cipher (hex): ')
                    cipher = self.getStream()
                    mess = rsa._decrypt(cipher)
                    self.pushStream(f"Your message: {mess}\n")
                else:
                    self.pushStream('Just type 1, 2, 3. Try again !!!\n')
            except socket.error as er:
                print(f"Error receiving/sending data from {self.addr}: {er}\n")
                print(f"{self.addr} disconnected")
                self.conn.close()
                break
    def getStream(self):
        return self.conn.recv(1024).decode('utf-8').strip()
    def pushStream(self, mess):
        self.conn.sendall(bytes(mess,'utf-8'))
class App:
    
    def __init__(self, host, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((host, port))
        self.socket.listen()
        print("Server listening on %s:%d" % (host, port))
    
    def listen(self):
        while True:
            try:
                conn, addr = self.socket.accept()
                new_user = User(conn, addr)
                threading.Thread(target=new_user.session).start()
                print(f"{addr} connected")
            # except KeyboardInterrupt:
            #     break
            except Exception as e:
                pass

if __name__ == '__main__':
    server = App('0.0.0.0',7777)
    server.listen()