from StringIO import StringIO
from OpenSSL import crypto
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
ssl_sock.write(struct.pack(">HBHH", 0, 7, 2, 3))
while True:
    resp = ssl_sock.read(3)
    if not resp:
        print "Disconnected"
        break
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
            myip = struct.unpack(">BBBB", pl.read(4))
            print "MY OR IP = ", myip
        numOfMyAddr = struct.unpack(">B", pl.read(1))[0]
        for i in range ( numOfMyAddr ):
            (typ,length) = struct.unpack(">BB", pl.read(2))
            if typ == 4 and length == 4:#IPv4 address
                ip = struct.unpack(">BBBB", pl.read(4))
                print "Server OR IP = ", ip
        print "FIN NETINFO"

        #respond with my net info - we're then good to go!
        mynetinf = struct.pack(">IBBBBBBBBB", time.time(), peerAddr[0], peerAddr[1], peerAddr[2], peerAddr[3], 1, myip[0], myip[1], myip[2], myip[3])
        ssl_sock.send(mynetinf)
    elif cmd == "AUTH_CHALLENGE": #response not needed for client-only
        challenge = pl.read(32)
        nmethods = struct.unpack(">H", pl.read(2))[0]
        methods = pl.read(2* nmethods)
        print "CHAL: ",hexlify(challenge),"NMETHODS: ", nmethods,"METHODS: ",hexlify(methods)
    else: #unknown packet
        print hexlify(payload)

