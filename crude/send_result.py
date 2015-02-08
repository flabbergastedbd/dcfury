import array
import socket
import sys
import zlib


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


username = "tunnelshade"
hub = (sys.argv[1], int(sys.argv[2]))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(hub)

s.send("$MyNick " + username + "|")
data = s.recv(2048)
print(data)

parts = data.replace('|', ' ').split(' ')
lock = parts[parts.index("$Lock") + 1]

s.send("$Lock EXTENDEDPROTOCOLABCABCABCABCABCABC Pk=DCPLUSPLUS0.843|")
s.send("$Direction Download 1|$Supports MiniSlots XmlBZList ADCGet TTHF ZLIG|$Key " + lock2key2(lock) + "|")

try:
    while True:
        data = s.recv(2048)
        if (len(data) != 0) and ("$ADCGET" in data.replace('|', ' ').split(' ')):
            print(data)
            s.send(data.replace("ADCGET", "ADCSND"))
            s.send(zlib.compress(open("test_file.txt", "r").read()))
except KeyboardInterrupt:
    s.close()
    exit()
