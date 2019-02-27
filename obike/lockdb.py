#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os


class LockDb(object):

    def __init__(self, db_file=os.path.join(
                 os.path.dirname(__file__), 'lockdb.txt')):
        self.lockdb = dict()
        with open(db_file) as f:
            for line in f:
                bikeno, lockno = line.strip().split(" ", 1)
                self.lockdb[lockno] = bikeno

    def lookup(self, lockno):
        return self.lockdb.get(lockno, None)


lockdb = LockDb()
