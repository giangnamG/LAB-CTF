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
        print("d: %s" %hex(pow(self.e,-1,self.phi)))
        return hex(pow(bytes_to_long(mess.encode('utf-8')), self.e,self.p*self.q))

    def decrypt(self, isGetFlag, enc, key):
        try:
            if isGetFlag:
                key = int(key, 16)
            else:
                key = self.d
            mess = long_to_bytes(pow(int(enc, 16), key, self.n)).decode('utf-8')
            return mess
        except Exception as e:
            return "Invalid Key"
    def process(self):
        print(self.title())
        while True:
            try:
                choice = int(input("Your choice: "))
                if choice == 1:
                    mess = input("What would you like to encrypt? Type here: ")
                    enc = self.encrypt(mess)
                    print(f"Here your cipher: {enc}")
                elif choice == 2:
                    enc = input("What would you like to decrypt? Type here: ")
                    data = self.decrypt(isGetFlag=False, enc=enc, key=None)
                    print(f"Here your data: {data}")
                elif choice == 3:
                    print(f"Here your encryption of the flag: {self.enc_flag}")
                elif choice == 4:
                    key = input("What is your key? Type here: ")
                    data = self.decrypt(isGetFlag=True, enc=self.enc_flag, key=key)
                    if data == self.flag:
                        print(f"Congratulation !! Please submit your flag and receive your reward !! {self.flag}")
                    else:
                        print(data)
                else:
                    print(self.title())
            except Exception as e:
                print("Something went wrong")
                
                
app = RSA()
app.process()