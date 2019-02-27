#!/usr/bin/env python
# -*- coding: utf-8 -*-

from obike.http_client import HttpClient

client = HttpClient()

f = open('lockdb.txt', 'w')
for i in range(1000, 9999):
    bikeid = '049%06d' % i
    lockno = client.lock_no(bikeid)
    print "%s %s" % (bikeid, lockno)
    f.write("%s %s\n" % (bikeid, lockno))

f.close()
