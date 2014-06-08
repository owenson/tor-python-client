import sys
import pprint
import binascii
import base64
import pprint
import urllib2
import zlib
flags = {}
router = {}

def getDoc(doc):
    return urllib2.urlopen("http://86.59.21.38/tor/"+doc).read()

def fetchConsensus():
    global router,flags
    consensus_txt = zlib.decompress(getDoc("status-vote/current/consensus.z"))
    total = 0
    curRouter = False

# Parse the consensus into a dict
    for l in consensus_txt.splitlines():
        q = l.strip().split(" ")
        if q[0] == 'r': #router descriptor
            rfmt = ['nick', 'identity', 'digest', 'pubdate', 'pubtime', 'ip', 'orport', 'dirport']
            data = dict(zip(rfmt, q[1:]))
            idt= data['identity']
            idt += "=" * (4-len(idt)%4) # pad b64 string
            ident = data['identity'] = base64.standard_b64decode(idt)
            data['identityhash'] = binascii.hexlify(ident)
            data['identityb32'] = base64.b32encode(ident).lower()
            router[ident] = data
            curRouter = ident
        if q[0] == 's': #flags description - add to tally totals too
            router[curRouter]['flags'] = q[1:]
            for w in q[1:]:
                if flags.has_key(w):
                    flags[w]+=1
                else:
                    flags[w] = 1
            total += 1
        if q[0] == 'v':
            router[curRouter]['version'] = ' '.join(q[1:])

# Fetch router descrition array given name
def getRouter(nm):
    for r in router.itervalues():
        if r['nick'] == nm:
            return r
    return None

# Fetch text router descriptor containing keys
def getRouterDescriptor(identityhash):
    if router[identityhash.decode('hex')]:
        return getDoc("server/fp/"+identityhash)
    return None

# parse router descriptor and return onion key in ber/der format for import into PyCrypto
def getRouterOnionKey(routerdesc):
    lns = routerdesc.splitlines()
    okidx = lns.index("onion-key") + 2
    onionk = ""
    while "END" not in lns[okidx]:
        onionk += lns[okidx]
        okidx += 1
    return base64.b64decode(onionk)

#gho = getRouter("gho")
#rtdesc = getRouterDescriptor(gho['identityhash'])
#okey = getRouterOnionKey(rtdesc)
#from Crypto.PublicKey import RSA
#print RSA.importKey(okey)
#print getDoc("server/fp/"+gho['identityhash'])
#pprint.pprint( router)
