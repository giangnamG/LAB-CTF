from Crypto.Util.number import bytes_to_long, getPrime, inverse

class RSA:
    def __init__(self):
        p, q = getPrime(512), getPrime(512)
        self.n = p*q
        self.e = 65537
        self.d = inverse(self.e,(p-1)*(q-1))
        self.flag = 'ISPCTF{}'
        
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
        print(self.title()+"\n")
        while True:
            try:
                choice = input('Your choice: ')
                if choice == '1':
                    cipher, e, n = self._encrypt(self.flag)
                    print(f"(cipher,e,n):({cipher},{e},{n})\n")
                elif choice == '2':
                    mess = input('What your message: ')
                    cipher, e, n = self._encrypt(mess)
                    print(f"(cipher,e,n):({cipher},{e},{n})\n")
                elif choice == '3':
                    cipher = input('What your cipher (hex): ')
                    mess = self._decrypt(cipher)
                    print(f"Your message: {mess}\n")
                else:
                    print('Just type 1, 2, 3. Try again !!!\n')
            except Exception as er:
                break
if __name__ == '__main__':
    user = RSA()
    user.session()