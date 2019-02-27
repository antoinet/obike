#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bluepy import btle
from hexdump import hexdump
from obike.lockdb import lockdb


class BleScanner(object):

    class ScanDelegate(btle.DefaultDelegate):

        def __init__(self):
            btle.DefaultDelegate.__init__(self)

        def handleDiscovery(self, dev, isNewDev, isNewData):
            if isNewDev:
                name = dev.getValueText(9)
                if name:
                    lockno = name[5:14]
                    bikeno = lockdb.lookup(lockno)
                    if name and name.startswith('bike:'):
                        print " [-] %s (%s, %s)" % (bikeno, dev.addr, name)

    def __init__(self, iface=0):
        self.scanner = btle.Scanner(iface).withDelegate(self.ScanDelegate())

    def scan(self, t=10):
        print "[*] scanning (%ds)..." % t
        devices = self.scanner.scan(t)
        # return [dev for dev in devices if dev.addr.upper().startswith('D4')]
        return devices
