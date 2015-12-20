import QRC
from QRC.Common import *


sh = random_hash()
ch = random_hash()
sc = QRC.AES(sh, ch)
cc = QRC.AES(sh, ch)
ot = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
se = sc.encrypt_client_data(ot)
cd = cc.decrypt_client_data(se)
print ot
print b64e(se)
print cd
ce = cc.encrypt_server_data(ot)
sd = sc.decrypt_server_data(ce)
print ot
print b64e(ce)
print sd
