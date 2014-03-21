from StringIO import StringIO
import pprint
import os
from OpenSSL import crypto
import time
import ssl,socket,struct
from binascii import hexlify
# cipher = AES CTR (ZERO IV START)
# HASH = SHA1
# RSA 1024bit, e=65537, OAEP
KEY_LEN=16
DH_LEN=128
DH_SEC_LEN=40
PK_ENC_LEN=128
PK_PAD_LEN=42
HASH_LEN=20
# hash of pub key = sha1 hash of der encoding of asn.1 rsa public key
#PKCS1_OAEP.PKCS1OAEP_Cipher(rsa, None, None, None)

#def hybridEncrypt(m, rsa):


cellTypes = {
         1: "CREATE",
         2: "CREATED",
         3: "RELAY",
         4: "DESTROY",
         5: "CREATE_FAST",
         6: "CREATED_FAST",
         8: "NETINFO",
         9: "RELAY_EARLY",
         10: "CREATE2",
         11: "CREATED2",
         7: "VERSIONS",
         128: "VPADDING",
         129: "CERTS",
         130: "AUTH_CHALLENGE",
         131: "AUTHENTICATE",
         132: "AUTHORIZE" }

def cellTypeToId(typ):
    return cellTypes.values().index(typ)

certTypes = {
        1: "LINK",
        2: "RSAIDENT",
        3: "RSA AUTH" }

class Cell(object):
    def __init__(self):
        pass
    def encode(self, circId, cell):
        s = struct.pack(">HB", circId, cell.cmdId)
        pl = cell.encode()
        plen  = 509
        if cell.cmdId == 7 or cell.cmdId == 127:
            plen = len(pl)
        if len(pl) < plen:
            pl += '\x00'*(plen-len(pl))
        return s + pl

    def decode(self, io):
        self.hdr = struct.unpack(">HB", io.read(3))
        self.cmd = cellTypes[self.hdr[1]]
        print "Got packet: ", self.cmd

        if self.hdr[1] > 127 or self.hdr[1] == 7: # var length packet
            plenbytes = io.read(2)
            self.plen = struct.unpack(">H", plenbytes)[0]
        else: #fixed length packet
            self.plen = 509

        self.payload = io.read(self.plen)
        print "hdr>", self.hdr, "pl>",hexlify(self.payload)
        return True

class CellCerts(object):
    def __init__(self):
        self.cmdId = cellTypeToId("CERTS")
        pass
    def decode(self,payload):
        pl = StringIO(payload)
        nCerts = struct.unpack(">B", pl.read(1))[0]
        self.certs = []
        for i in range(nCerts):
            (cType, cLen) = struct.unpack(">BH", pl.read(3))
            self.certs.append ( {'cType': certTypes[cType], 'data': pl.read(cLen) } )
        return True

class CellNetInfo(object):
    def __init__(self):
        self.cmdId = cellTypeToId("NETINFO")
        pass
    def decode(self,payload):
        pl = StringIO(payload)
        stime = struct.unpack(">I", pl.read(4))[0]
        (typ,length) = struct.unpack(">BB", pl.read(2))

        if typ == 4 and length == 4: #IPv4 address
            self.myip = struct.unpack(">BBBB", pl.read(4))

        numOfServAddr = struct.unpack(">B", pl.read(1))[0]
        self.serveraddresses = []
        for i in range ( numOfServAddr ):
            (typ,length) = struct.unpack(">BB", pl.read(2))
            if typ == 4 and length == 4:#IPv4 address
                ip = struct.unpack(">BBBB", pl.read(4))
                self.serveraddresses.append(ip)
        return True
    def encode(self):
# time(4)  remote ip(4,4, ..ip..), numMyAddr=1, myip(4,4, ...ip...)
        s = struct.pack(">I", time.time())
        s += struct.pack(">BB4B", 4, 4, *self.serveraddresses[0])
        s += struct.pack(">BBB4B", 1, 4, 4, *self.myip)
        return s

# set versions = [ .... ]
class CellVersions(object):
    def __init__(self):
        self.cmdId = cellTypeToId("VERSIONS")
        pass
    def decode(self, payload):
        self.versions = []
        for i in range(len(payload)/2):
                self.versions.append( struct.unpack(">H", payload[i*2:i*2+2])[0] )
    def encode(self):
        st = struct.pack(">H", len(self.versions)*2)
        for v in self.versions:
            st += struct.pack(">H", v)
        return st

print "Generating RSA IDENTITY KEY"
pkey_ident =crypto.PKey()
pkey_ident.generate_key(crypto.TYPE_RSA, 1024)
cert_ident = crypto.X509()
cert_ident.get_subject().CN = "wwww.ghowen.me"
cert_ident.set_serial_number(1000)
cert_ident.gmtime_adj_notBefore(0)
cert_ident.gmtime_adj_notAfter(10*365*24*60*60)
cert_ident.set_issuer(cert_ident.get_subject())
cert_ident.set_pubkey(pkey_ident)
cert_ident.sign(pkey_ident, 'sha1')

s = socket.socket()
ssl_sock = ssl.wrap_socket(s)
ssl_sock.connect(("86.59.21.38", 443))
peerAddr= [int(x) for x in ssl_sock.getpeername()[0].split(".")]
#VERSIONS Cell circid=0 cmd=7 len=2 ver=3
#ssl_sock.write(struct.pack(">HBHH", 0, 7, 2, 3))
c = Cell()
cv = CellVersions()
cv.versions = [3]
pkt = c.encode(0, cv)
ssl_sock.write(pkt)
while True:
    c = Cell()
    c.decode(ssl_sock)

    if c.cmd == "CERTS":
        cc = CellCerts()
        if cc.decode(c.payload):
            print "certs decoded ok"
    elif c.cmd == "VERSIONS":
        cv = CellVersions()
        if cv.decode(c.payload):
            print "versions decoded ok"
    elif c.cmd == "NETINFO":
        cni = CellNetInfo()
        if cni.decode(c.payload):
            print "netinfo decoded ok"

        mycni = c.encode(0,cni)
        ssl_sock.send(mycni)    #respond with my netinfo my reversing info sent by server

        x = os.urandom(HASH_LEN)
        ssl_sock.send(struct.pack(">HB", 5, cellTypeToId("CREATE_FAST")) + x + '\x00'*(509-HASH_LEN))

    elif c.cmd == "AUTH_CHALLENGE": #response not needed for client-only
        pl = StringIO(c.payload)
        challenge = pl.read(32)
        nmethods = struct.unpack(">H", pl.read(2))[0]
        methods = pl.read(2* nmethods)
        print "CHAL: ",hexlify(challenge),"NMETHODS: ", nmethods,"METHODS: ",hexlify(methods)
    else: #unknown packet
        print c.cmd,c.hdr[1],"??>", hexlify(c.payload)

