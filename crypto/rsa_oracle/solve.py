from pwn import remote
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, inverse

# r = remote('127.0.0.1',7778)
r = remote('157.245.192.100',7778)
print(r.recvuntil(b'Your choice: ').decode('utf-8'))
r.sendline(b'1')
print(1)
data = r.recvuntil(b'Your choice: ').decode('utf-8')
cipher, e, N = data[16:][:-15].split(',')
e, N = int(e), int(N)
cipher = bytes_to_long(bytes.fromhex(cipher))
print(f"{cipher}, {e}, {N}")

upper_limit = N
lower_limit = 0

flag = ""
i = 1
# for 1024 bit N

def _decrypt(r,chosen_ct):
    print(chosen_ct)
    r.sendline(b'3')
    print('choice: 3')
    print(r.recvuntil(b'What your cipher (hex): ').decode('utf-8'))
    r.sendline(str(hex(chosen_ct)).encode('utf-8'))
    print(str(hex(chosen_ct)))
    return int(r.recvuntil(b'Your choice: ')[14:][:-14].decode('utf-8'))
    

_decrypt(r, cipher)
while i <= 1024:
    chosen_ct = (cipher*pow(2**i, e, N)) % N
    output = _decrypt(r,chosen_ct)
    try:
        if output == 0:
            upper_limit = (lower_limit + upper_limit)//2
        elif output == 1:
            lower_limit = (lower_limit + upper_limit)//2
    except Exception as e:
        print(e)
    i += 1

# # Decrypted ciphertext
print(long_to_bytes(upper_limit).decode('utf-8'))