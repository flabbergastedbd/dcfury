#!/usr/bin/python

import re
import os
import bz2
import ssl
import sys
import glob
import time
import array
import base64
import codecs
import random
import socket
import xml.etree.ElementTree as ET

from sqlalchemy import create_engine, exc, func, select
from sqlalchemy.orm import scoped_session, sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy import Table, Column, BigInteger, String, Boolean,\
    Float, DateTime, ForeignKey, Text, Integer

Base = declarative_base()

# This table actually allows us to make a many to many relationship
# between transactions table and grep_outputs table
file_association_table = Table(
    'user_file_association',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id')),
    Column('file_tth', String, ForeignKey('files.tth'))
)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    nick = Column(String, unique=True)
    hub = Column(String)
    ip = Column(String)
    info = Column(String)
    files = relationship(
        "File",
        secondary=file_association_table,
        backref="users")

    @hybrid_property
    def collected_share(self):
        size = 0
        for f in self.files:
            size += f.size
        return size

    @hybrid_property
    def share(self):
        share = 0
        try:
            if self.info is not None:
                share = int(self.info.strip('$').split('$')[-1])
        except (TypeError, ValueError):
            pass
        return(share)

    @hybrid_property
    def email(self):
        email = None
        if self.info is not None:
            email = self.info.strip('$').split('$')[-2]
        return email

    @hybrid_property
    def done(self):
        return((self.collected_share >= 0.8*self.share))


class File(Base):
    __tablename__ = "files"

    tth = Column(String, primary_key=True)
    name = Column(String)
    path = Column(String)
    size = Column(BigInteger)

    @hybrid_property
    def num_users(self):
        return(len(self.users))


def lock2key(lock):
    """
    Generates response to $Lock challenge from Direct Connect Servers
    """
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


class ProgressBar(object):
    def __init__(self, total, current=0):
        self.total = total
        self.current = current
        self._print((self.current*100)/self.total, start=True)

    def update_bar(self, current):
        self.current = current
        self._print((self.current*100)/self.total)

    def _print(self, percent, start=False):
        if start == False:
            sys.stdout.write('\r')
            sys.stdout.flush()
        sys.stdout.write('[' + '='*(percent) + ' '*(100-percent) + '] ' + ('%3d %%'%(percent)))
        sys.stdout.flush()


class NMDCClient(object):
    def __init__(
            self,
            host,
            port,
            db_settings,
            username="anonymous_x",
            password=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self._db_settings = db_settings
        self.nicks = []
        # hub used for db purposes
        self.hub = host + ":" + str(port)
        self._connect_db()

    @staticmethod
    def _unicode(string):
        # print(string)
        # print(type(string))
        if isinstance(string, unicode):
            result = string
        else:
            try:
                result = unicode(string, encoding="utf-8")
            except UnicodeDecodeError:
                result = string.decode("latin1").encode("utf-8", "replace")
        return result

    def _connect_db(self):
        try:
            self.engine = create_engine(
                "postgresql+psycopg2://{0}:{1}@{2}:{3}/{4}".format(
                    self._db_settings['DATABASE_USER'],
                    self._db_settings['DATABASE_PASS'],
                    self._db_settings['DATABASE_IP'],
                    self._db_settings['DATABASE_PORT'],
                    self._db_settings['DATABASE_NAME']),
                client_encoding='utf8')
            Base.metadata.create_all(self.engine)
            session_factory = sessionmaker(bind=self.engine)
            self.session = scoped_session(session_factory)
        except exc.OperationalError as e:
            print("[*] Unable to connect to db")
            print(e)
            sys.exit(1)

    def connect_hub(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.s.setblocking(0)  # Necessary
        self.s.settimeout(5)
        self.s.connect((self.host, self.port))
        # For the first time, as soon as we connect
        # we get lock and hub name
        data = self.s.recv(1024)
        while not data.endswith('|'):
            data += self.s.recv(1024)
        print("[*] Lock command from hub")
        print(data)
        lock = re.findall("\$Lock ([^\s]*)", data)[0]
        self.s.send("$Supports UserCommand UserIP2 TTHSearch GetZBlock|")
        self.s.send("$Key " + lock2key(lock) + "|")
        self.s.send("$ValidateNick " + self.username + "|")
        data = self.s.recv(1024)
        print(data)
        # If password is asked, then submit what we have
        if re.findall("\$GetPass\|", data) and password is not None:
            self.s.send("MyPass " + self.password)
        self.s.send("$Version 1,0091|")
        self.s.send("$MyINFO $ALL " + self.username + " <StrgDC++ V:2.41,M:P,H:9/3/0,S:5>$ $0.011$$60028339050$|")
        # Done handshake, now ask for nick list and move on
        self.s.send("$GetNickList|")
        self._wait_and_process("NickList")

    def _wait_and_process(self, substring):
        data = ''
        while (not data.endswith('|') or substring not in data):
            try:
                data += self.s.recv(1024)
            except socket.timeout:
                pass
            if len(data) == 0:
                return
        print("[*] Wait and process")
        print(data)
        self._process_commands(data)

    def _process_commands(self, data):
        commands = data.split('|')
        for command in commands:
            if command.startswith("$NickList"):
                self.nicks = command.split(' ')[-1].strip('$').split("$$")
                self.nicks = set([self._unicode(x) for x in self.nicks])
                print("[*] Obtained nick list")
                print(self.nicks)
                self.add_users(self.nicks)
            elif command.startswith("$MyINFO $ALL"):
                nick, info = re.findall("\$MyINFO \$ALL ([^\s]*) (.*)", command)[0]
                nick = self._unicode(nick)
                info = self._unicode(info)
                print("[*] Received info about %s" % (nick))
                print(command)
                self.nicks.add(nick)
                user = self.get_user(nick)
                if user is None:
                    self.add_user(nick)
                self.update_user(nick, info=info)
            elif command.startswith("$UserIP"):
                nick, ip = re.findall("\$UserIP ([^\s]*) (.*)", command)[0]
                nick = self._unicode(nick)
                print("[*] Received ip of %s" % (nick))
                print(command)
                self.update_user(nick, ip=ip)
            elif command.startswith("$Quit"):
                nick = re.findall("\$Quit ([^\|]*)", command)[0]
                nick = self._unicode(nick)
                print("[*] %s quit" % (nick))
                print(command)
                self.nicks.remove(nick)
            elif command.startswith("$ConnectToMe"):
                own_nick, addr, param, nick = re.findall("\$ConnectToMe ([^\s]*) ([0-9\.\:]*)(NS|S|RS)?\s?(.*)?", command)[0]
                print("[*] Received Connect from %s" % (nick))
                print(command)
                if param == "S":
                    self.get_file_list(addr, nick, tls=True)
                elif param == "NS":
                    self.get_file_list(addr, nick, tls=True, nat=True)
                elif param == "N":
                    self.get_file_list(addr, nick, tls=False, nat=True)
                else:
                    self.get_file_list(addr, nick, tls=False)
            elif command.startswith("$RevConnectToMe"):
                other_nick, own_nick = re.findall("\$RevConnectToMe ([^\s]*) (.*)", command)[0]
                self.listen_file_list(other_nick)
                print("[*] RevConnect from %s" % (other_nick))

    def listen_file_list(self, nick, tls=False):
        orig_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # orig_s.settimeout(10)
        orig_s.bind(("0.0.0.0", 0))
        orig_s.listen(5)
        print("[*] Listening for connection on %s:%d" % (self.s.getsockname()[0], orig_s.getsockname()[1]))
        self.s.sendall("$ConnectToMe %s %s:%d|" % (nick, self.s.getsockname()[0], orig_s.getsockname()[1]))
        try:
            (conn, addr) = orig_s.accept()
            print("[*] Connection obtained from %s:%d" % (addr[0], addr[1]))
        except socket.error:
            s.close()
            orig_s.close()
            return
        # Start handshake
        conn.send("$MyNick " + self.username + "|")
        # We should send the lock and later send their lock solution
        conn.send("$Lock EXTENDEDPROTOCOLABCABCABCABCABCABC Pk=DCPLUSPLUS0.843|")
        data = conn.recv(1024)
        while not data.endswith('|'):
            data += conn.recv(1024)
        print("[*] Lock of other client")
        print(data)
        lock = re.findall("\$Lock ([^\s]*)", data)[0]
        nick = re.findall("\$MyNick ([^\|]*)\|", data)[0]
        conn.send("$Direction Download 31745|")
        conn.send("$Supports MiniSlots XmlBZList ADCGet TTHF ZLIG|")
        conn.send("$Key " + lock2key(lock) + "|")
        data += conn.recv(1024)
        while not data.endswith('|'):
            data += conn.recv(1024)
        nick = self._unicode(nick)
        self.update_user(nick, ip=addr[0])
        print("[*] Support and direction of other client")
        print(data)
        action, num = re.findall("\$Direction ([^\s]*) ([0-9]*)\|", data)[0]
        conn.send("$ADCGET file files.xml.bz2 0 -1|")
        data = conn.recv(1024)  # Receive ADCSND
        print("[*] Expecting ADCSND")
        print(data)
        name, size = re.findall("\$ADCSND file ([^\s]+) 0 ([0-9]+)\|", data)[0]
        # There is a chance of some data being read
        total_size = int(size)
        data = data.split('|')[-1] if len(data.split('|')) > 1 else ''
        recv_size = len(data)
        bar = ProgressBar(total_size, current=recv_size)
        while recv_size < total_size:
            extra = conn.recv(1024*5)
            data += extra
            recv_size += len(extra)
            bar.update_bar(recv_size)
        xml_data = bz2.decompress(data)
        file_path = self.write_file_list(xml_data, nick)
        print("\n[*] File list uncompressed and written to %s" % (file_path))
        # et = ET.fromstring(xml_data)
        # self.save_files(et, nick)
        conn.close()
        orig_s.close()

    def get_file_list(self, addr, nick, nat=False, tls=False):
        print("[*] Trying to connect on %s" % (addr))
        s_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_.bind(("0.0.0.0", 0))
        s_.settimeout(5)
        if tls == True:
            print("[*] OMG, we have to use TLS")
            s = ssl.wrap_socket(s_, ssl_version=ssl.PROTOCOL_SSLv23)
        else:
            s = s_
        if nat == True:
            command = ("$ConnectToMe %s %s:%d" + ("RS" if tls else "R") + " %s|") % (nick, self.s.getsockname()[0], s.getsockname()[1], self.username)
            print("[*] Responding to NAT connect request")
            print(command)
            self.s.sendall(command)
        host, port = addr.split(':')
        try:
            s.connect((host, int(port)))
        except socket.error:
            s.close()
            return
        # Start handshake
        try:
            s.send("$MyNick " + self.username + "|")
            data = s.recv(1024)
            while not data.endswith('|'):
                data += s.recv(1024)
            print("[*] Lock of other client")
            print(data)
            lock = re.findall("\$Lock ([^\s]*)", data)[0]
            # We should send the lock and later send their lock solution
            s.send("$Lock EXTENDEDPROTOCOLABCABCABCABCABCABC Pk=DCPLUSPLUS0.843|")
            s.send("$Direction Download 31745|")
            s.send("$Supports MiniSlots XmlBZList ADCGet TTHF ZLIG|")
            s.send("$Key " + lock2key(lock) + "|")
            data += s.recv(1024)
            while not data.endswith('|'):
                data += s.recv(1024)
            nick = re.findall("\$MyNick ([^\|]*)\|", data)[0]
            nick = self._unicode(nick)
            self.update_user(nick, ip=host)
            print("[*] Support and direction of other client")
            print(data)
            action, num = re.findall("\$Direction ([^\s]*) ([0-9]*)\|", data)[0]
            s.send("$ADCGET file files.xml.bz2 0 -1|")
            data = s.recv(1024) # Receive ADCSND
            print("[*] Expecting ADCSND")
            print(data)
            name, size = re.findall("\$ADCSND file ([^\s]+) 0 ([0-9]+)\|", data)[0]
            # There is a chance of some data being read
            total_size = int(size)
            data = data.split('|')[-1] if len(data.split('|')) > 1 else ''
            recv_size = len(data)
            print("[*] File list download. Total size: %d" % (total_size))
            bar = ProgressBar(total_size, current=recv_size)
            while recv_size < total_size:
                extra = s.recv(1024*500)
                data += extra
                recv_size += len(extra)
                bar.update_bar(recv_size)
            xml_data = bz2.decompress(data)
            file_path = self.write_file_list(xml_data, nick)
            print("\n[*] File list uncompressed and written to %s" % (file_path))
            # et = ET.fromstring(xml_data)
            # self.save_files(et, nick)
        except socket.error:
            pass
        finally:
            s.close()

    @staticmethod
    def get_save_path(nick):
        return os.path.join("file_lists", base64.b64encode(nick) + ".xml")

    def write_file_list(self, data, nick):
        path = self.get_save_path(nick)
        with codecs.open(path, "w", encoding="utf-8") as f:
            f.write(self._unicode(data))
        return(path)

    def downloaded_file_list(self, nick):
        return os.path.isfile(self.get_save_path(nick))

    def save_files(self, xml_root, nick, prepend_path=None):
        user = self.get_user(nick)
        if user is not None:
            for item in xml_root:
                if item.tag == "File":
                    file_name = item.get("Name")
                    file_size = int(item.get("Size"))
                    file_tth = item.get("TTH")
                    if prepend_path is not None:
                        file_path = prepend_path
                    else:
                        file_path = ''
                    # print("[*] File TTH: %s Name: %s" % (file_tth, file_name))
                    file_obj = self.session.query(File).get(file_tth)
                    if file_obj is None:
                        file_obj = File(
                            tth=file_tth,
                            name=self._unicode(file_name),
                            size=file_size,
                            path=self._unicode(file_path))
                        file_obj.users = [user]
                    else:
                        if user not in file_obj.users:
                            file_obj.users.append(user)
                elif item.tag == "Directory":
                    if prepend_path is not None:
                        path = os.path.join(prepend_path, item.get("Name"))
                    else:
                        path = item.get("Name")
                    print("[*] Going for files inside %s" % (path))
                    if "Program Files" not in path:
                        self.save_files(item, nick, prepend_path=self._unicode(path))
                    else:
                        file_obj = self.session.query(File).get("SHIT")
                        if file_obj is None:
                            file_obj = File(
                                tth="SHIT",
                                name="Program Files",
                                size=1024,
                                path=self._unicode(path))
                            file_obj.users = [user]
                        else:
                            if user not in file_obj.users:
                                file_obj.users.append(user)
        self.session.commit()

    def add_users(self, nick_list):
        for nick in nick_list:
            if not self.get_user(nick):
                user = User(nick=nick, hub=self.hub)
                # self.s.send("$GetINFO %s %s|" % (nick, self.username))
                self.session.add(user)
                # self._wait_and_process("$MyINFO $ALL")
        self.session.commit()

    def add_user(self, nick):
        self.add_users([nick])

    def update_user(self, nick, info=None, ip=None):
        user = self.get_user(nick)
        if info is not None:
            user.info = info
        if ip is not None:
            user.ip = ip
        self.session.commit()

    def get_user(self, nick):
        user = None
        users = self.session.query(User).filter_by(nick=nick).all()
        if len(users) > 0:
            user = users[0]
        return user

    @staticmethod
    def _get_nick(nick_list):
        # Temp bans
        while True:
            nick = random.sample(nick_list, 1)[0]
            if 'N3XT' in nick:
                continue
            elif nick in ['VIPChat', 'RegChat', 'Chinu']:
                continue
            return nick

    def get_file_lists(self):
        print("[*] Will be looping over nicks for collecting file lists")
        collected_nicks = set([self.username])
        filenames = os.listdir(os.path.join(os.path.dirname(__file__), "file_lists"))
        for name in filenames:
            collected_nicks.add(base64.b64decode(name.split('.')[0]))
        nick_list_copy = self.nicks.difference(collected_nicks)
        while len(nick_list_copy) > 0:
            print("[*] Selecting randomly from %d who are sorted from %d" % (len(nick_list_copy), len(self.nicks)))
            nick = self._get_nick(nick_list_copy)
            tries = 0
            print("[*] Checking if we already have file list for %s" % (nick))
            while not self.downloaded_file_list(nick) and tries < 3:
                print("[*] It seems we don't")
                print("[*] Sending a RevConnectMe to %s" % (nick))
                self.s.send("$RevConnectToMe %s %s|" % (self.username, nick))
                self._wait_and_process("ConnectToMe")
                tries += 1
            # Update using new data
            if self.downloaded_file_list(nick):
                collected_nicks.add(nick)
            nick_list_copy = self.nicks.difference(collected_nicks)

    def add_files_to_db(self):
        print("[*] Will be looping over fetched file lists")
        os.chdir("file_lists")
        for f in glob.glob("*.xml"):
            nick = base64.b64decode(f.split('.')[0])
            if os.path.isfile(f + '.done'):
                print("[*] %s files are already in db" % (nick))
                continue
            else:
                print("[*] Checking if nick (%s) is already in db" % (nick))
                user = self.get_user(nick)
                if user is None:
                    print("[*] Nick (%s) not in db, so adding" % (nick))
                    self.add_user(nick)
                    user = self.get_user(nick)
                tries = 0
                share_size = user.share
                collected_share_size = user.collected_share
                print("[*] Share size extracted from info: " + str(share_size))
                print("[*] Share size collected from list: " + str(collected_share_size))
                if collected_share_size == 0:
                    xml_data = codecs.open(f, "r").read()
                    et = ET.fromstring(xml_data)
                    self.save_files(et, nick)
                else:
                    done_file = open(f+'.done', 'w')
                    done_file.close()

    def _shell(self):
        try:
            while True:
                i = raw_input("> ")
                self.s.send(i)
                try:
                    data = self.s.recv(1024)
                    print(data)
                except socket.timeout:
                    pass
        except KeyboardInterrupt:
            pass
        finally:
            self.s.close()

db_settings = {}
db_settings["DATABASE_IP"] = "127.0.0.1"
db_settings["DATABASE_PORT"] = "5432"
db_settings["DATABASE_NAME"] = "dcrawl"
db_settings["DATABASE_USER"] = "crawl_bot"
db_settings["DATABASE_PASS"] = "crawl_bot"
# hub = NMDCClient("192.168.1.3", 4112, db_settings)
# hub = NMDCClient("adc.mimic.cz", 1511, db_settings)
# hub = NMDCClient("docohub.com", 1511, db_settings)
hub = NMDCClient("10.8.11.41", 4112, db_settings)
# hub = NMDCClient("10.8.20.21", 4112, db_settings)
# hub._do_shit()
if 'collect' in sys.argv:
    hub.connect_hub()
    hub.get_file_lists()
elif 'analyse' in sys.argv:
    hub.add_files_to_db()
# hub._shell()
