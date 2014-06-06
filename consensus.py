import sys
import pprint
import binascii
import base64
import pprint
import urllib2
flags = {}
router = {}
total = 0
curRouter = False

print "fetching consensus"

def getDoc(doc):
    return urllib2.urlopen("http://86.59.21.38/tor/"+doc).read()

consensus_txt = getDoc("status-vote/current/consensus")

for l in consensus_txt.splitlines():
    q = l.strip().split(" ")
    if q[0] == 'r': #router descriptor
        rfmt = ['nick', 'identity', 'digest', 'pubdate', 'pubtime', 'ip', 'opport', 'dirport']
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

def getRouter(nm):
    for r in router.itervalues():
        if r['nick'] == nm:
            return r
    return None

def getRouterDescriptor(identityhash):
    if router[identityhash.decode('hex')]:
        return getDoc("server/fp/"+identityhash)
    return None



#gho = getRouter("gho")
#print getRouterDescriptor(gho['identityhash'])
#print getDoc("server/fp/"+gho['identityhash'])
#pprint.pprint( router)
