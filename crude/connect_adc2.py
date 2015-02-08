import md5
import sys
import base64
import socket

try:
    username = sys.argv[1]
except IndexError:
    username = "geronimo_anonymous"
private_id = "YYYY"
base_pid = base64.b32encode(private_id)
client_id = md5.md5(private_id).hexdigest().upper()
base_cid = base64.b32encode(client_id)
base_cid = "XTUR2G2SR5HZKAQYLRINPS6YXCHT5XO4VFZLTQQ"

hub = ("192.168.1.3", 4112)
# hub = ("support.flexhub.org", 8000)
# hub = ("adc.mimic.cz", 1511)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(hub)

s.send("HSUP ADBASE ADTIGR MD5\n")
data = s.recv(2048)
commands = data.split('\n')
for i in commands:
    if i.startswith("ISID"):
        session_id = i.split(' ')[1]
print(data.replace("\\n", "\n"))

# print("PID: " + base_pid)
# print("CID: " + base_cid)
# print("SID: " + session_id)
data = "BINF " + session_id + " ID" + base_cid + " PD" + base_pid + " "
data += "HN0 HR1 HO2 NI" + username  + " SL5 SF898 SS1142\n"
s.send(data)
data = s.recv(2048)
print(data.replace("\\n", "\n"))

s.send("BMSG " + session_id + " stupid\n")

while True:
    data = s.recv(2048)
    if len(data) != 0:
        print(data.replace("\\n", "\n"))
    else:
        break

s.close()
