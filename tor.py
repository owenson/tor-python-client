from StringIO import StringIO
import pprint
import os
from OpenSSL import crypto
import time
import ssl,socket,struct
from binascii import hexlify
from Crypto.Hash import SHA
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

# cell superclass
# can instatiate any subclass and call pack() to send
# calling unpack on Cell will return correct subclass (if exists)
class Cell(object):
    def __init__(self):
        self.payload = None
        self.cmdId = None
        self.circId = 0
        self.hdr = None
    def pack(self, cell=None):
        if cell==None:
            cell = self
        print self.__class__.__name__, (self.circId, cell.cmdId)

        s = struct.pack(">HB", self.circId, cell.cmdId)
        self.pl = cell.encode()
        self.plen  = 509
        if cell.cmdId == 7 or cell.cmdId == 127:
            self.plen = len(self.pl)
        if len(self.pl) < self.plen:
            self.pl += '\x00'*(self.plen-len(self.pl))
        return s + self.pl

    def unpack(self, io):
        self.hdr = struct.unpack(">HB", io.read(3))
        self.cmd = cellTypes[self.hdr[1]]
        print "Got packet: ", self.cmd

        if self.hdr[1] > 127 or self.hdr[1] == 7: # var length packet
            plenbytes = io.read(2)
            self.plen = struct.unpack(">H", plenbytes)[0]
        else: #fixed length packet
            self.plen = 509

        self.payload = io.read(self.plen)
        cell = None
        if self.cmd == "VERSIONS":
            cell = CellVersions(self.payload)
        elif self.cmd == "CERTS":
            cell = CellCerts(self.payload)
        elif self.cmd == "NETINFO":
            cell = CellNetInfo(self.payload)
        else:
            cell = CellUnkown(self.payload)
        cell.circId = self.hdr[0]
        cell.cmdId = self.hdr[1]
        cell.hdr = self.hdr
        cell.payload = self.payload

        print "hdr>", self.hdr, "pl>",hexlify(self.payload)
        return cell

class CellUnkown(Cell):
    def __init__(self, pkt=None):
        Cell.__init__(self)
    def decode(self, payload):
        Cell.payload = payload

class CellCerts(Cell):
    def __init__(self, pkt=None):
        Cell.__init__(self)
        self.cmdId = cellTypeToId("CERTS")
        if pkt!=None:
            self.decode(pkt)
    def decode(self,payload):
        pl = StringIO(payload)
        nCerts = struct.unpack(">B", pl.read(1))[0]
        self.certs = []
        for i in range(nCerts):
            (cType, cLen) = struct.unpack(">BH", pl.read(3))
            self.certs.append ( {'cType': certTypes[cType], 'data': pl.read(cLen) } )
        return True

class CellNetInfo(Cell):
    def __init__(self, pkt=None):
        Cell.__init__(self)
        self.cmdId = cellTypeToId("NETINFO")
        if pkt!=None:
            self.decode(pkt)
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
        Cell.payload = s
        return s

# set versions = [ .... ]
class CellVersions(Cell):
    def __init__(self,pkt=None):
        Cell.__init__(self)
        self.cmdId = cellTypeToId("VERSIONS")
        if pkt!=None:
            self.decode(pkt)
        pass
    def decode(self, payload):
        self.versions = []
        for i in range(len(payload)/2):
                self.versions.append( struct.unpack(">H", payload[i*2:i*2+2])[0] )
    def encode(self):
        st = struct.pack(">H", len(self.versions)*2)
        for v in self.versions:
            st += struct.pack(">H", v)
        Cell.payload = st
        return st

# recv next cell from network and return it
# if cmd specified (class name), then wait for that cell and return it - discard others
def recv_cell(io, cmd=None):
    while True:
        c = Cell()
        cell = c.unpack(io)
        print "Recv cell ", cell.__class__.__name__
        if cmd==None:
            return cell
        elif cell.__class__.__name__ == cmd:
            return cell
        print "Ignoring cell"

#Tor KDF function
def kdf_tor(K0, length):
    K = ''
    i = 0
    while len(K) < length:
        K += SHA.new(K0 + chr(i)).digest()
        i+=1
    return K


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

# Send our versions cell to get started
cv = CellVersions()
cv.versions = [3]
ssl_sock.write(cv.pack())

# Wait for NetInfo, ignoring others and then send our netinfo
cnetinf = recv_cell(ssl_sock, 'CellNetInfo')
ssl_sock.send(cnetinf.pack())

# Handshakes complete
x = os.urandom(HASH_LEN)
ssl_sock.send(struct.pack(">HB", 5, cellTypeToId("CREATE_FAST")) + x + '\x00'*(509-HASH_LEN))
ccreatedfast = recv_cell(ssl_sock)
y = ccreatedfast.payload[:HASH_LEN]
derkd = ccreatedfast.payload[HASH_LEN:2*HASH_LEN]
print hexlify(x),hexlify(y),hexlify(derkd)
KK = StringIO(kdf_tor(x+y, 3*HASH_LEN + 2*KEY_LEN))
(KH, Df, Db) = [KK.read(HASH_LEN) for i in range(3)]
(Kf, Kb) = [KK.read(KEY_LEN) for i in range(2)]
if derkd != KH:
    print "Key check failed"
print hexlify(KH)

#while True:
#    cell = recv_cell(ssl_sock)
#    print cell.__class__.__name__
#
#    if isinstance(cell, CellNetInfo):
#        mycni = cell.pack()
#        ssl_sock.send(mycni)    #respond with my netinfo my reversing info sent by server
#
#        x = os.urandom(HASH_LEN)
#        ssl_sock.send(struct.pack(">HB", 5, cellTypeToId("CREATE_FAST")) + x + '\x00'*(509-HASH_LEN))
#
##    elif c.cmd == "AUTH_CHALLENGE": #response not needed for client-only
##        pl = StringIO(c.payload)
##        challenge = pl.read(32)
##        nmethods = struct.unpack(">H", pl.read(2))[0]
##        methods = pl.read(2* nmethods)
##        print "CHAL: ",hexlify(challenge),"NMETHODS: ", nmethods,"METHODS: ",hexlify(methods)
#    else: #unknown packet
#        print cellTypes[cell.cmdId],cell.hdr[1],"??>", hexlify(cell.payload)
#
