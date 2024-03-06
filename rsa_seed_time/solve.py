from pwn import remote
import random, time
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime, inverse

r = remote('127.0.0.1',7777)
random.seed(int(time.time()))

data = r.recvuntil(b'Your choice:').decode('utf-8')
print(data)
r.sendline(b'4')
data = r.recvuntil(b'Type here: ')
def getPrime(num):
        if num % 2 == 0:
            num += 1
        while not isPrime(num):
            num += 2
        return num
p = getPrime(random.getrandbits(512))
q = getPrime(random.getrandbits(512))
e = 65537
d = str(hex(inverse(e, (p-1)*(q-1)))).encode('utf-8')
r.sendline(d)
data = r.recvuntil(b'Your choice:').decode('utf-8')
print(data)
