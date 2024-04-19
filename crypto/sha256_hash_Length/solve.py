import base64, json, HashTools
from pwn import remote, context

# r = remote('167.71.223.49',3000)
r = remote('157.245.192.100',7779)
# context.log_level = 'debug'
print("-------------------------Wait response from server------------------------")

a = r.recvuntil(b'>>> ')
print(a)
data = {
    "do": "register",
    "name": "ngn"
}
r.sendline(json.dumps(data).encode('utf8'))
res = r.recvuntil(b'>>> ').decode('utf8').replace(">>>","").strip()
# res = "bmFtZT1uZ24mYWRtaW49RmFsc2U=.F/KtxF+pCzS7fNF48i5KmlslGqekN0m9c5p5IwtF3iU="
print(res)
data, old_token = res.split(".")
original_data = base64.b64decode(data)
old_token = base64.b64decode(old_token).hex()
print("original_data: ", original_data)
print("old token: ", old_token)

length = 32
append_data = b"name=ngn&admin=True"
magic = HashTools.new("sha256")
new_data, new_sig = magic.extension(
    secret_length=length, original_data=original_data,
    append_data=append_data, signature=old_token
)
print("new_data: ", new_data, len(new_data))
print("new_sig: ", new_sig, len(bytes.fromhex(new_sig)))
payload = {
    "do" : "login",
    "token": (base64.b64encode(new_data) + b'.' + base64.b64encode(bytes.fromhex(new_sig))).decode("utf-8")
}
payload = json.dumps(payload).encode("utf-8")
print("payload: ", payload)
r.sendline(payload)
data = r.recv().decode("utf-8")
pos = data.find("ISPCTF{")
print("flag: ",data[pos:])