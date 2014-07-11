import socket, ssl
from torfuncs import *
bindsocket = socket.socket()
bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
bindsocket.bind(('0.0.0.0', 9001))
bindsocket.listen(5)

newsocket, fromaddr = bindsocket.accept()
connstream = ssl.wrap_socket(newsocket,
        server_side=True,
        certfile="server.crt",
        keyfile="server.key",
        ssl_version=ssl.PROTOCOL_TLSv1)

while True:
    c = decodeCell(connstream)
    if(c[0] == 7):
        print "send ver"
        connstream.send(buildCell(0, 7, [00, 03]))

    print c

