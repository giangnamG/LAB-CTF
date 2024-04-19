from os import environ
from dotenv import load_dotenv
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from flask import Flask, request, make_response, Response
from base64 import b64encode, b64decode

import sys
import json

load_dotenv()

FLAG = environ['FLAG']
PORT = int(environ['PORT'])

default_session = '{"admin": true, "username": "guest"}'
key = get_random_bytes(AES.block_size)
app = Flask(__name__)


def encrypt(session):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return b64encode(iv + cipher.encrypt(pad(session.encode('utf-8'), AES.block_size)))


def decrypt(session):
    raw = b64decode(session)
    cipher = AES.new(key, AES.MODE_CBC, raw[:AES.block_size])
    try:
        return unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size).decode()
    except Exception:
        return None


@app.route('/')
def index():
    session = request.cookies.get('session')
    if session == None:
        res = Response(open(__file__).read(), mimetype='text/plain')
        s = encrypt(default_session)
        res.set_cookie('session', encrypt(default_session).decode())
        s = decrypt(s)
        print(1,json.loads(s))
        return res
    elif (plain_session := decrypt(session)) == default_session:
        print(2,json.loads(plain_session), type(plain_session))
        return Response(open(__file__).read(), mimetype='text/plain')
    else:
        if plain_session != None:
            
            try:
                if json.loads(plain_session)['admin'] == True:
                    return FLAG
                else:
                    return 'You are not an administrator 1'
            except Exception:
                return 'You are not an administrator 2'
        else:
            return 'You are not an administrator 3'

if __name__ == '__main__':
    app.run('0.0.0.0', PORT)