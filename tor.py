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
ssl_sock.connect(("gho.dyndns.org", 9001))
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
    print hexlify(payload)
    if cmd == "CERTS":
        nCerts = struct.unpack(">B", payload[0])[0]
        print "Got ", nCerts, " certificates"
        offset = 1
        for i in range(nCerts):
            (cType, cLen) = struct.unpack(">BH", payload[offset:offset+3])
            offset +=3
            print "Certificate: ", cType, certTypes[cType]
            f = open("cert."+certTypes[cType]+"."+str(i), "w")
            f.write(payload[offset:offset+cLen])
            f.close()
            offset += cLen

