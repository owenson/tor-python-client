from StringIO import StringIO
import binascii
from collections import namedtuple
import pprint
import os
from OpenSSL import crypto
import time
import ssl,socket,struct
from binascii import hexlify
from Crypto.Hash import SHA
from Crypto.Cipher import *
from Crypto.PublicKey import *
import sys
from Crypto.Util import Counter
import consensus

from torfuncs import *

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

        return buildCell(self.circId, self.cmdId, cell.encode());

    def unpack(self, io):
        self.circId, self.cmdId, self.payload = decodeCell(io)
        self.cmd = cellTypes[self.cmdId]
        print "Got packet: ", self.cmd

        cell = None
        if self.cmd == "VERSIONS":
            cell = CellVersions(self.payload)
        elif self.cmd == "CERTS":
            cell = CellCerts(self.payload)
        elif self.cmd == "NETINFO":
            cell = CellNetInfo(self.payload)
        else:
            cell = CellUnkown(self.payload)
        cell.circId = self.circId
        cell.cmdId = self.cmdId
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

class TorCircuit():
    def __init__(self, sock, circid):
        self.hops = []
        self.circId = circid
        self.socket = sock
        self.tempX = 0
        self.packetCount = 0

#parse relaycell as str
    def encrypt(self, relayCell):
        for hop in self.hops[::-1]:
            relayCell = hop.encrypt(relayCell)
        return relayCell

#parse relaycell as str
    def decrypt(self, relayCell):
        for hop in self.hops:
            relayCell = hop.decrypt(relayCell)
        return relayCell

#firsthop as hash str
    def create(self, firstHop):
        (self.tempX, create) = buildCreatePayload(firstHop)
        createcell = buildCell(self.circId, cellTypeToId("CREATE"), create)
        self.socket.send(createcell)

#parse full torcell
    def handleCreated(self, cell):
        assert cell.cmdId == cellTypeToId("CREATED")
        created = cell.payload
        t1 = decodeCreatedCell(created, self.tempX)
        self.hops.append(t1)

    def extend(self, hopHash):
        (self.tempX,extend)=buildExtendPayload(hopHash)
        extendr = buildRelayCell(self.hops[-1], relayTypeToCmdId("RELAY_EXTEND"), 0, extend)
        extendr = self.encrypt(extendr)
        self.socket.send(buildCell(self.circId, cellTypeToId("RELAY_EARLY"), extendr))

#parse full torcell
    def handleExtended(self, cell):
        assert cell.cmdId == cellTypeToId("RELAY")
        extended = self.decrypt(cell.payload)
        relayDec = decodeRelayCell(extended)

        assert relayDec['relayCmd'] == relayTypeToCmdId("RELAY_EXTENDED")
        t2 = decodeCreatedCell(relayDec['payload'], self.tempX)
        self.hops.append(t2)


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

print "getting consensus"
consensus.fetchConsensus()

s = socket.socket()
ssl_sock = ssl.wrap_socket(s)
ssl_sock.connect(("94.242.246.24", 8080))
peerAddr= [int(x) for x in ssl_sock.getpeername()[0].split(".")]

# Send our versions cell to get started
cv = CellVersions()
cv.versions = [3]
ssl_sock.write(cv.pack())

# Wait for NetInfo, ignoring others and then send our netinfo
cnetinf = recv_cell(ssl_sock, 'CellNetInfo')
ssl_sock.send(cnetinf.pack())

# CREATE CIRCUIT TO FIRST HOP
circ = TorCircuit(ssl_sock, 1)
circ.create("orion")
created = recv_cell(ssl_sock)
if created.cmdId != cellTypeToId("CREATED"):
    print "errr not created"

circ.handleCreated(created)

# extend circuit
for hop in ["gho", "southsea0", "tor26", "gho", "southsea0", "tor26", "gho", "southsea0"]:
    circ.extend(hop)
    extended = recv_cell(ssl_sock)
    print ">>>-", extended
    circ.handleExtended(extended)


#if extended.cmdId != cellTypeToId("EXTENDED"):
#    print "errr not EXTENDED"


# RECEIVE CREATED CELL

##Build DIR CONNECT (ignore slashdot stuff, just junk payload
#hostrel = "www.slashdot.org:80"
#pktresolv = hostrel +"\x00"
#pktrelayresolv = buildRelayCell(t1, 13, 1, pktresolv)
#final = buildCell(1, cellTypeToId("RELAY_EARLY"), pktrelayresolv)
##
#ssl_sock.send(final)
#
##this should be connected response

#r = consensus.getRouter("gho")

# EXTEND CIRCUIT - BUILD EXTEND CELL


#print struct.unpack(">BHHLH", relay_reply[:11])
#
#print "decrypted: ", binascii.hexlify(relay_reply[11:])

#print relay_reply[2:]
#
##now send HTTP Request and loop through response packets
#reldat = buildRelayCell(t1, 2, 1, "GET /tor/status-vote/current/consensus HTTP/1.0\r\n\r\n")
#final = struct.pack(">HB", 5, cellTypeToId("RELAY_EARLY")) + reldat
#ssl_sock.send(final)
#
#
#while True:
#    relay_reply = recv_cell(ssl_sock)
#    relay_reply = t1.bwdCipher.decrypt(relay_reply.payload)
#    print struct.unpack(">BHHLH", relay_reply[:11])
#
#    print "decrypted: ", binascii.hexlify(relay_reply[11:])
#    print relay_reply[11:]

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
