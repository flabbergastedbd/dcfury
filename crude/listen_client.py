#!/usr/bin/python

import array
import socket


def lock2key2(lock):
    "Generates response to $Lock challenge from Direct Connect Servers"
    lock = array.array('B', lock)
    ll = len(lock)
    key = list('0'*ll)
    for n in xrange(1,ll):
        key[n] = lock[n]^lock[n-1]
    key[0] = lock[0] ^ lock[-1] ^ lock[-2] ^ 5
    for n in xrange(ll):
        key[n] = ((key[n] << 4) | (key[n] >> 4)) & 255
    result = ""
    for c in key:
        if c in (0, 5, 36, 96, 124, 126):
            result += "/%%DCN%.3i%%/" % c
        else:
            result += chr(c)
    return result

orig_s = socket.socket()
orig_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
orig_s.bind(("192.168.1.1", 9090))
orig_s.listen(5)

s, address = orig_s.accept()
data = s.recv(2048)
print(data)

data = data.split(" ")
lock = data[data.index("winxp2|$Lock")+1]
s.send("$Key " + lock2key2(lock) + "|$Lock " + lock + " Pk=DCPLUSPLUS0.777|$HubName tunnelshade|")

try:
    while True:
        input_data = raw_input("> ")
        if len(input_data) != 0:
            s.send(input_data)
        data = s.recv(2048)
        print(data)
except KeyboardInterrupt:
    orig_s.close()
    s.close()
