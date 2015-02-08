#!/usr/bin/python

import re
import array
import socket


def lock2key2(lock):
    "Generates response to $Lock challenge from Direct Connect Servers"
    lock = array.array('B', lock)
    ll = len(lock)
    key = list('0'*ll)
    for n in xrange(1, ll):
        key[n] = lock[n] ^ lock[n-1]
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


username = "geronimo_anonymous"
# hub = ("192.168.1.3", 4112)
# hub = ("dc.tiera.ru", 411)
# hub = ("10.8.11.41", 4112)
# hub = ("LordJohns-Place.no-ip.org", 6666)

udp_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(hub)

data = s.recv(1024)
print(data)

lock = data.split(" ")[1]
s.send("$Supports UserCommand UserIP2 TTHSearch GetZBlock|")
s.send("$Key " + lock2key2(lock) + "|")
s.send("$ValidateNick " + username + "|")

data = s.recv(1024)
print(data)

s.send("$Version 1,0091|$MyINFO $ALL " + username + " <StrgDC++ V:2.41,M:P,H:9/3/0,S:5>$ $0.011$$60028339050$|")
data = s.recv(2048)
print(data)
data = s.recv(2048)
print(data)

# s.send("$To: winxp2 From: " + username + " $<" + username + "> Hey, I am the admin |")
# s.send("<" + username + "> Hey guys, I am actually " + username + "|")
data = s.recv(2048)
print(data)

try:
    while True:
        input_data = ""
        #input_data = raw_input("> ")
        if len(input_data) != 0:
            s.send(input_data)
        data = s.recv(2048)
        if len(data) != 0:
            print(str(data))
            for command in re.findall("(?<=\$)(UserCommand.*?)(?=\|)", data):
                print(command)
            for command in re.findall("(?<=\$)(Search.*?)(?=\|)", data):
                parts = command.split(' ')
                index = parts.index("Search")
                client_string = parts[index+1]
                client = client_string.split(":")
                client[1] = int(client[1])
                client = tuple(client)
                search_string = parts[index+2]
                search_term = ' '.join(search_string.split('?')[4:])
                if not search_term.startswith("TTH:"):
                    print("%s => %s" % (str(client_string), search_term.replace('$', ' ')))
                    # message = "$SR " + username + " F:_\Fake_" + search_term + ".txt\x0510 4/5\x05TTH:FRG76EDDQH37K5SR67FMR7J5LN2RSB3QAH33YKY (" + hub[0] + ":" + str(hub[1]) + ")|"
                    # udp_s.sendto(message, client)
except KeyboardInterrupt:
    s.close()
