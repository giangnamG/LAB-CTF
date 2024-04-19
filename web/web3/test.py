from json import loads, dumps

a = {
    "admin": True,
    "username": "guest"
}

print(a, type(a))
d = dumps(a)
print(d, type(d))
l = loads(d)
print(l, type(l))
x = '{"admin": true, "username": "guest"}'
print(loads(x))