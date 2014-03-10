from StringIO import StringIO
import time
import ssl,socket,struct
from binascii import hexlify

cmds = {
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

certTypes = {
        1: "LINK",
        2: "RSAIDENT",
        3: "RSA AUTH" }

s = socket.socket()
ssl_sock = ssl.wrap_socket(s)
ssl_sock.connect(("86.59.21.38", 443))
#VERSIONS Cell circid=0 cmd=7 len=2 ver=3
ssl_sock.write(struct.pack(">HBHH", 0, 7, 2, 3))
while True:
    resp = ssl_sock.read(3)
    print "hdr>>", hexlify(resp)
    hdr = struct.unpack(">HB", resp[:3])
    print hdr
    cmd = cmds[hdr[1]]
    print "Got packet: ", cmd

    if hdr[1] > 127 or hdr[1] == 7: # var length packet
        plenbytes = ssl_sock.read(2)
        plen = struct.unpack(">H", plenbytes)[0]
    else: #fixed length packet
        plen = 509

    payload = ssl_sock.read(plen)
    pl = StringIO(payload) # io object, just to make sequential reading easier
    if cmd == "CERTS":
        nCerts = struct.unpack(">B", pl.read(1))[0]
        print "Got ", nCerts, " certificates"
        for i in range(nCerts):
            (cType, cLen) = struct.unpack(">BH", pl.read(3))
            print "Certificate: ", cType, certTypes[cType]
            f = open("cert."+certTypes[cType]+"."+str(i), "w")  # write server certs to a file
            f.write(pl.read(cLen))
            f.close()
    elif cmd == "NETINFO":
        pl = StringIO(payload)
        stime = struct.unpack(">I", pl.read(4))[0]
        print "Server Time: ", time.ctime(stime)
        (typ,length) = struct.unpack(">BB", pl.read(2))
        if typ == 4 and length == 4: #IPv4 address
            ip = struct.unpack(">BBBB", pl.read(4))
            print "MY OR IP = ", ip
        numOfMyAddr = struct.unpack(">B", pl.read(1))[0]
        for i in range ( numOfMyAddr ):
            (typ,length) = struct.unpack(">BB", pl.read(2))
            if typ == 4 and length == 4:#IPv4 address
                ip = struct.unpack(">BBBB", pl.read(4))
                print "Server OR IP = ", ip
        print "FIN NETINFO"
    elif cmd == "AUTH_CHALLENGE":
        challenge = pl.read(32)
        nmethods = struct.unpack(">H", pl.read(2))[0]
        methods = pl.read(2* nmethods)
        print "CHAL: ",hexlify(challenge),"NMETHODS: ", nmethods,"METHODS: ",hexlify(methods)
    else:
        print hexlify(payload)

