from obike.http_client import HttpClient

client = HttpClient()

f = open('lockdb.txt', 'w')
for i in range(9999, 11000):
    bikeid = '041%06d' % i
    lockno = client.lock_no(bikeid)
    print "%s %s" % (bikeid, lockno)
    f.write("%s %s\n" % (bikeid, lockno))

f.close()


