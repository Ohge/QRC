import QRC
from QRC.Common import *

a = QRC.KeyRing()
ap = a.public_key()
print "Alice public:", b64e(ap)
b = QRC.KeyRing()
bp = b.public_key()
print "Bob public:", b64e(bp)
ac = b.peer(ap)
bc = a.peer(bp)
ts = "Hello Bob!"
print "Message:", ts
es = a.encrypt(bc, ts)
print "Encrypted:", b64e(es)
ds = b.decrypt(ac, es)
print "Decrypted:", ds
ts = "Hello Alice!"
print "Message:", ts
es = b.encrypt(ac, ts)
print "Encrypted:", b64e(es)
ds = a.decrypt(bc, es)
print "Decrypted:", ds
